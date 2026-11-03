"""Gather live state from every node and Cloudflare account, and turn it into alert rules.

Used by the Overview / Tunnels APIs and by the background alert engine.
Every alert has a stable `key` (kind + target) so the engine can follow it from
firing to resolved even when its message text changes.
"""
from __future__ import annotations

import asyncio

import httpx

from . import cloudflared, haproxy
from .cfapi import CFError
from .config import CFAccount, Tunnel
from .sshpool import NodeError
from .state import st


async def safe(coro, node):
    try:
        return await coro
    except (NodeError, OSError) as e:
        return {"node": node.name, "host": node.host, "site": getattr(node, "site", ""), "error": str(e)}


def match_edge(cf_tunnels: list[dict], ref: str) -> dict | None:
    if not ref:
        return None
    for t in cf_tunnels:
        if t["id"] == ref or t["name"] == ref:
            return t
    return None


def tunnel_ref(n_name: str, t: dict) -> str:
    return t["config"].get("tunnel", "") or st.inv.token_ids.get((n_name, t["name"]), "")


def pick_edge(edge: dict, account: str, ref: str) -> tuple[str, dict | None, str | None]:
    """Find the CF tunnel for a local tunnel: explicit account, else search every account."""
    if account:
        a = edge.get(account) or {"tunnels": [], "error": "unknown account"}
        return account, match_edge(a["tunnels"], ref), a["error"]
    errs = []
    for name, a in edge.items():
        m = match_edge(a["tunnels"], ref)
        if m:
            return name, m, None
        if a["error"]:
            errs.append(f"{name}: {a['error']}")
    return "", None, ("; ".join(errs) or None)


async def resolve_edge(n_name: str, t: Tunnel, ref: str) -> tuple[CFAccount | None, dict | None]:
    edge = await st.cf.all_tunnels()
    acc_name, e, _ = pick_edge(edge, t.cf_account, ref)
    return (st.s.cf_accounts.get(acc_name) if acc_name else None), e


async def node_status(n):
    ts = await st.inv.tunnels(n)
    return await cloudflared.status(st.pool, n, ts, st.inv.token_ids)


async def tunnels_full(with_dns: bool = True) -> dict:
    nodes, edge = await asyncio.gather(
        asyncio.gather(*(safe(node_status(n), n) for n in st.s.cloudflared_nodes)),
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
            acc_name, e, err = pick_edge(edge, t["cf_account"], tunnel_ref(n["node"], t))
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


async def collect_all() -> tuple[list[dict], dict]:
    hp, tun = await asyncio.gather(
        asyncio.gather(*(safe(haproxy.status(st.pool, n), n) for n in st.s.haproxy_nodes)),
        tunnels_full(with_dns=True))
    return list(hp), tun


def kpis(hp: list[dict], tun: dict) -> dict:
    servers = [s for n in hp for be in n.get("backends", []) for s in be["servers"]]
    tunnels = [t for n in tun["nodes"] for t in n.get("tunnels", [])]
    return {
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


def build_alerts(hp: list[dict], tun: dict, has_cf_accounts: bool) -> tuple[list[dict], dict]:
    """Return (alerts, unknown) where `unknown` says which scopes could not be checked this
    round (unreachable nodes, failing CF accounts) so their alerts are not wrongly resolved."""
    a: list[dict] = []
    unknown = {"nodes": set(), "cf": False}

    def add(sev, kind, node, target, msg, sub=""):
        a.append({"key": f"{kind}|{target}{'|' + sub if sub else ''}", "kind": kind, "sev": sev,
                  "node": node, "where": target, "msg": msg})

    for n in hp:
        nn = n["node"]
        if n.get("error"):
            unknown["nodes"].add(nn)
            add("crit", "node.unreachable", nn, nn, n["error"])
            continue
        if n["service"]["active"] != "active":
            add("crit", "hp.service", nn, nn, f"haproxy service is {n['service']['active']}")
        if n.get("stats_error"):
            unknown["nodes"].add(nn)
            add("warn", "hp.stats", nn, nn, n["stats_error"])
        for be in n.get("backends", []):
            if be.get("status") == "DOWN":
                add("crit", "hp.backend_down", nn, f"{nn} / {be['name']}", "backend DOWN — no servers available")
            for s in be["servers"]:
                if s["status"].startswith("DOWN"):
                    add("warn", "hp.server_down", nn, f"{nn} / {be['name']}/{s['name']}",
                        f"server {s['status']} ({s.get('check_status') or 'no check'} {s.get('check_desc') or ''})".strip())
    for acc, v in tun["accounts"].items():
        if v["error"]:
            unknown["cf"] = True
            add("warn", "cf.account", "", f"CF account {acc}", v["error"])
    for n in tun["nodes"]:
        nn = n["node"]
        if n.get("error"):
            unknown["nodes"].add(nn)
            add("crit", "node.unreachable", nn, nn, n["error"])
            continue
        for t in n["tunnels"]:
            w = f"{nn} / {t['name']}"
            if t["service"]["active"] != "active":
                add("crit", "tun.service", nn, w, f"{t['unit']} is {t['service']['active']}")
            if t["config"].get("error"):
                add("crit", "tun.config", nn, w, t["config"]["error"])
            e = t.get("edge")
            if t.get("edge_error"):
                unknown["cf"] = True
            if has_cf_accounts and not e and not t.get("edge_error"):
                add("warn", "tun.not_found", nn, w,
                    "tunnel not found in any configured Cloudflare account (check 'tunnel:' in config.yml)")
            if e and e["status"] in ("down", "inactive"):
                add("crit", "tun.edge_down", nn, w, f"Cloudflare edge status: {e['status']}")
            elif e and e["status"] == "degraded":
                add("warn", "tun.edge_degraded", nn, w,
                    f"Cloudflare edge status: degraded ({len(e['connections'])} connections)")
            if (t.get("dns") or {}).get("error"):
                unknown["cf"] = True
            for r in (t.get("dns") or {}).get("routes", []):
                if r["status"] != "ok":
                    add("warn", f"dns.{r['status']}", nn, w, f"DNS {r['hostname']}: {r['detail']}", sub=r["hostname"])
    order = {"crit": 0, "warn": 1}
    return sorted(a, key=lambda x: order.get(x["sev"], 2)), unknown
