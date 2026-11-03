"""Monitoring and Traffic APIs: sites, servers, watched services, graphs, Settings → Monitoring,
the weekly summary, and the Traffic page (Cloudflare per site, HAProxy per frontend/backend)."""
from __future__ import annotations

import csv
import io
import json
import re
import shlex
import time

from fastapi import APIRouter, Body, Request
from fastapi.responses import Response

from . import monitor, sites, traffic
from .monitor import series, uptime, valid_unit
from .sshpool import NodeError
from .state import audit, need, shielded, st

router = APIRouter(prefix="/api")
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
URL_RE = re.compile(r"^(https?|tcp)://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?(/[^\s]*)?$")


def _site(r: dict, cfg: dict) -> dict:
    state = json.loads(r["state"] or "{}")
    opts = json.loads(r["opts"] or "{}")
    rt = json.loads(r["route"] or "{}")
    side = "pub" if state.get("pub") else "int"
    ms = series([f"site.{side}.ms:{r['host']}", f"site.{side}.up:{r['host']}"], "24h")
    return {"host": r["host"], "kind": r["kind"], "source": r["source"], "internal": r["internal"], "route": rt,
            "opts": opts, "excluded": bool(r["excluded"]), "state": state,
            "uptime24": uptime(f"site.{side}.up:{r['host']}", 86400),
            "uptime7": uptime(f"site.{side}.up:{r['host']}", 7 * 86400),
            "spark": [v for _, v in ms[f"site.{side}.ms:{r['host']}"]][-72:],
            "slow_ms": int(opts.get("slow_ms") or cfg["slow_ms"])}


def _servers() -> list[dict]:
    kinds = [("haproxy", st.s.haproxy_nodes), ("cloudflared", st.s.cloudflared_nodes), ("server", st.s.server_nodes)]
    health = {r["node"]: (json.loads(r["data"]), r["at"]) for r in st.store.db.q("SELECT * FROM health")}
    watched = st.monitor.watched() if getattr(st, "monitor", None) else {}
    out = []
    for kind, lst in kinds:
        for n in lst:
            h, at = health.get(n.name, ({}, 0))
            out.append({"name": n.name, "kind": kind, "host": n.host, "at": at, **h,
                        "watched": [{"unit": u, "state": (h.get("services") or {}).get(u, "unknown")}
                                    for u in watched.get(n.name, [])]})
    return out


@router.get("/monitor")
async def monitor_page():
    cfg = st.store.monitor_cfg()
    rows = st.store.db.q("SELECT * FROM checks ORDER BY host")
    items = [_site(r, cfg) for r in rows]
    active = [s for s in items if not s["excluded"]]
    servers = _servers()
    certs = [{"where": f"{c['node']}: {c['file']}", "days": c["days"], "subject": c.get("subject", "")}
             for c in (st.store.get("certs", {}) or {}).get("items", [])]
    certs += [{"where": s["host"], "days": s["state"]["cert"]["days"], "subject": s["state"]["cert"].get("issuer", ""),
               "public": True} for s in active if "days" in (s["state"].get("cert") or {})]
    pub_ms = sorted(s["state"]["pub"]["ms"] for s in active
                    if (s["state"].get("pub") or {}).get("ok") and s["state"]["pub"].get("ms"))
    up = sum(1 for s in active if s["state"].get("status") in ("up", "slow"))
    ok_srv = [s for s in servers if s.get("at") and not s.get("error")]
    healthy = sum(1 for s in ok_srv if (s.get("fullest") or {}).get("pct", 0) < cfg["disk_warn"]
                  and (s.get("mem_pct") or 0) < cfg["mem_crit"])
    svcs = [w for s in servers for w in s["watched"]]
    m = st.monitor if getattr(st, "monitor", None) else None
    day = monitor.local_day(time.time(), cfg)
    top_be = [r["name"] for r in st.store.db.q(
        "SELECT name FROM traffic_daily WHERE source='hp' AND day=? AND name LIKE '%/be:%' ORDER BY requests DESC LIMIT 4",
        (day,))]
    return {
        "top_backends": top_be, "hp_nodes": [n.name for n in st.s.haproxy_nodes],
        "kpi": {"sites_up": up, "sites_total": len(active),
                "down": [s["host"] for s in active if s["state"].get("status") == "down"],
                "median_ms": pub_ms[len(pub_ms) // 2] if pub_ms else None,
                "servers_ok": healthy, "servers_total": len(servers),
                "services_ok": sum(1 for w in svcs if w["state"] == "active"), "services_total": len(svcs),
                "cert_next": min(certs, key=lambda c: c["days"]) if certs else None},
        "sites": items, "servers": servers, "certs": sorted(certs, key=lambda c: c["days"]),
        "settings": {k: cfg[k] for k in ("check_every", "health_every", "slow_ms", "disk_warn", "disk_crit",
                                         "mem_crit", "load_factor")},
        "last_run": m.last_run if m else 0, "error": (m.last_error or m.discover_error) if m else "",
    }


@router.get("/monitor/series")
async def monitor_series(names: str, range: str = "24h", agg: str = "avg"):
    lst = [n for n in names.split(",") if n][:40]
    return {"range": range, "series": series(lst, range, "sum" if agg == "sum" else "avg")}


@router.post("/monitor/run")
@shielded
async def monitor_run(request: Request):
    need(request, "operator")
    await st.monitor.tick(force=True)
    return {"ok": True}


@router.put("/monitor/sites/{host}")
async def site_update(request: Request, host: str, body: dict = Body(...)):
    need(request, "operator")
    r = st.store.db.one("SELECT * FROM checks WHERE host=?", (host,))
    if not r:
        raise KeyError(f"no check for {host}")
    opts = json.loads(r["opts"] or "{}")
    for k in ("path", "keyword"):
        if k in body:
            v = str(body[k] or "").strip()
            if k == "path" and v and (not v.startswith("/") or " " in v or len(v) > 200):
                raise ValueError("path must start with / and have no spaces")
            if len(v) > 120:
                raise ValueError(f"{k} is too long")
            opts[k] = v
    for k, lo, hi in (("expect", 100, 599), ("slow_ms", 50, 60000)):
        if k in body:
            v = str(body[k] or "").strip()
            if v and not (v.isdigit() and lo <= int(v) <= hi):
                raise ValueError(f"{k} must be {lo}-{hi}")
            opts[k] = int(v) if v else None
    if "public" in body:
        opts["public"] = bool(body["public"])
    internal = r["internal"]
    if r["source"] == "manual" and "internal" in body:
        internal = str(body["internal"] or "").strip()
        if internal and not URL_RE.match(internal):
            raise ValueError("internal address must look like http://10.0.10.21:8080 or tcp://10.0.10.21:25565")
    excl = int(bool(body.get("excluded", r["excluded"])))
    st.store.db.x("UPDATE checks SET opts=?, excluded=?, internal=? WHERE host=?",
                  (json.dumps(opts), excl, internal, host))
    audit(request, "monitor site", host, True, json.dumps({**opts, "excluded": bool(excl)}))
    if not excl:
        await st.monitor.check_sites(st.store.monitor_cfg(), only=host)
    return {"ok": True}


@router.post("/monitor/sites")
async def site_add(request: Request, body: dict = Body(...)):
    need(request, "operator")
    host = str(body.get("host", "")).strip().lower()
    kind = "tcp" if body.get("kind") == "tcp" else "http"
    internal = str(body.get("internal") or "").strip()
    if not HOST_RE.match(host):
        raise ValueError("enter a hostname like shop.example.com")
    if internal and not URL_RE.match(internal):
        raise ValueError("internal address must look like http://10.0.10.21:8080 or tcp://10.0.10.21:25565")
    if kind == "tcp" and not internal:
        raise ValueError("a TCP check needs an address (tcp://host:port)")
    if st.store.db.one("SELECT 1 FROM checks WHERE host=?", (host,)):
        raise ValueError(f"{host} is already checked")
    t = int(time.time())
    opts = {"public": kind == "http" and bool(body.get("public", True))}
    st.store.db.x("INSERT INTO checks (host, kind, source, internal, opts, seen_at, created_at) VALUES (?,?,?,?,?,?,?)",
                  (host, kind, "manual", internal, json.dumps(opts), t, t))
    audit(request, "monitor site add", host, True, internal)
    await st.monitor.check_sites(st.store.monitor_cfg(), only=host)
    return {"ok": True}


@router.delete("/monitor/sites/{host}")
async def site_delete(request: Request, host: str):
    need(request, "operator")
    r = st.store.db.one("SELECT source FROM checks WHERE host=?", (host,))
    if not r:
        raise KeyError(f"no check for {host}")
    if r["source"] != "manual":
        raise ValueError("this site was found automatically — use “Don't check” instead")
    st.store.db.x("DELETE FROM checks WHERE host=?", (host,))
    audit(request, "monitor site delete", host, True)
    return {"ok": True}


@router.post("/monitor/services")
async def service_add(request: Request, body: dict = Body(...)):
    need(request, "operator")
    node, unit = str(body.get("node", "")), str(body.get("unit", "")).strip()
    st.s.node(node)
    if "." not in unit:
        unit += ".service"
    if not valid_unit(unit):
        raise ValueError("service name: letters, digits and _ . @ : - only")
    st.store.db.x("INSERT OR IGNORE INTO services (node, unit, created_at) VALUES (?,?,?)", (node, unit, int(time.time())))
    audit(request, "watch service", f"{node}:{unit}", True)
    await st.monitor.read_health(st.store.monitor_cfg())
    return {"ok": True, "unit": unit}


@router.delete("/monitor/services/{node}/{unit}")
async def service_delete(request: Request, node: str, unit: str):
    need(request, "operator")
    st.store.db.x("DELETE FROM services WHERE node=? AND unit=?", (node, unit))
    audit(request, "unwatch service", f"{node}:{unit}", True)
    return {"ok": True}


@router.post("/monitor/services/restart")
@shielded
async def service_restart(request: Request, body: dict = Body(...)):
    need(request, "operator")
    node, unit = str(body.get("node", "")), str(body.get("unit", ""))
    n = st.s.node(node)
    if not st.store.db.one("SELECT 1 FROM services WHERE node=? AND unit=?", (node, unit)) or not valid_unit(unit):
        raise ValueError("only watched services can be restarted here")
    q = shlex.quote(unit)
    try:
        r = await st.pool.run(n, f"systemctl restart {q} 2>&1; sleep 2; systemctl is-active {q}", timeout=90, critical=True)
    except NodeError as e:
        audit(request, "service restart", f"{node}:{unit}", False, str(e))
        raise
    ok = r.out.strip().splitlines()[-1:] == ["active"] if r.out.strip() else False
    audit(request, "service restart", f"{node}:{unit}", ok, r.text[-500:])
    await st.monitor.read_health(st.store.monitor_cfg())
    return {"ok": ok, "output": r.text}


@router.get("/monitor/services/suggest/{node}")
async def service_suggest(request: Request, node: str):
    need(request, "operator")
    n = st.s.node(node)
    r = await st.pool.run(n, "systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null "
                             "| awk '{print $1}' | head -200", root=False)
    skip = re.compile(r"^(systemd-|dbus|getty|serial-getty|user@|cron|rsyslog|ssh|polkit|networkd|ifup|console-|"
                      r"unattended|packagekit|udisks|accounts-daemon|snapd|multipathd|qemu-guest|chrony|lxcfs)")
    return {"units": [u for u in r.out.split() if u.endswith(".service") and not skip.match(u)]}


# ---- Settings → Monitoring -----------------------------------------------------------
@router.get("/admin/monitor")
async def monitor_settings(request: Request):
    need(request, "superadmin")
    try:
        size = st.store.db.one("SELECT page_count * page_size AS b FROM pragma_page_count(), pragma_page_size()")["b"]
    except Exception:
        size = None
    excluded = [r["host"] for r in st.store.db.q("SELECT host FROM checks WHERE excluded=1 ORDER BY host")]
    return {"settings": st.store.monitor_cfg(), "db_bytes": size, "excluded": excluded,
            "summary_sent": st.store.get("summary_sent")}


@router.put("/admin/monitor")
async def monitor_settings_save(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    m = st.store.set_monitor(body)
    audit(request, "monitor settings", "monitoring", True, json.dumps(body)[:500])
    return {"ok": True, "settings": m}


@router.post("/admin/monitor/summary")
async def summary_now(request: Request):
    need(request, "superadmin")
    text = await st.monitor.weekly(st.store.monitor_cfg(), force=True)
    audit(request, "weekly summary", "test", True)
    return {"ok": True, "text": text}


# ---- Traffic ---------------------------------------------------------------------------
@router.get("/traffic")
async def traffic_page(range: str = "7d"):
    return await traffic.report(range)


@router.post("/traffic/refresh")
@shielded
async def traffic_refresh(request: Request):
    need(request, "operator")
    await traffic.collector.maybe_refresh(force=True)
    return {"ok": True, "status": st.store.get("traffic_status", {})}


@router.get("/traffic.csv")
async def traffic_csv(range: str = "7d", tab: str = "cf"):
    rep = await traffic.report(range)
    buf = io.StringIO()
    csv.writer(buf).writerows(traffic.csv_rows(rep, "hp" if tab == "hp" else "cf"))
    name = f"traffic-{'haproxy' if tab == 'hp' else 'sites'}-{rep['range']}-{rep['days'][1]}.csv"
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---- CF Tunnels: routes and per-host numbers --------------------------------------------
async def enrich_tunnels(data: dict, hp_status: list[dict]) -> dict:
    """Add each ingress rule's route (→ HAProxy frontend → backend, servers up), its site status from
    Monitoring and today's / 7 days' requests; plus per-tunnel totals for the CF Tunnels page."""
    models = await sites.hp_models()
    checks = {r["host"]: json.loads(r["state"] or "{}") for r in st.store.db.q("SELECT host, state FROM checks")}
    cfg = st.store.monitor_cfg()
    days = [monitor.local_day(time.time() - i * 86400, cfg) for i in range(7)][::-1]
    q = ",".join("?" * len(days))
    req: dict[str, dict] = {}
    for r in st.store.db.q(f"SELECT day, name, requests FROM traffic_daily WHERE source='cf' AND day IN ({q})", days):
        req.setdefault(r["name"], {})[r["day"]] = r["requests"]
    for n in data.get("nodes", []):
        for t in n.get("tunnels", []):
            tot = [0] * 7
            for rule in t["config"].get("ingress", []):
                h = (rule.get("hostname") or "").lower()
                rt = sites.route(models, h, rule.get("service", ""))
                if rt["backend"]:
                    up = sites.servers_up(hp_status, rt["hp_node"], rt["backend"])
                    if up:
                        rt["up"], rt["total"] = up
                rule["route"] = rt
                s = checks.get(h) or {}
                p = s.get("pub") or s.get("int") or {}
                rule["site"] = {"status": s.get("status"), "code": p.get("code"), "ms": p.get("ms")} if s else None
                daily = [req.get(h, {}).get(d, 0) for d in days]
                rule["today"] = daily[-1]
                rule["week"] = daily
                tot = [a + b for a, b in zip(tot, daily)]
            t["requests_week"] = tot
            t["requests_today"] = tot[-1]
    data["traffic_days"] = days
    return data

