"""Alerts API: active and historical alerts, acknowledge, mutes, CSV export, run-now."""
from __future__ import annotations

import csv
import io
import re
import time

from fastapi import APIRouter, Body, Request
from fastapi.responses import Response

from . import sites
from .alerts import FLAP_QUIET, is_muted
from .config import NAME_RE
from .state import audit, need, scope, st, user

router = APIRouter(prefix="/api")
SEVS = ("warn", "crit")


def _decorate(rows: list[dict], t: int) -> list[dict]:
    mutes = st.engine.mutes(t)
    out = []
    for r in rows:
        a = {"key": r["key"], "node": r["node"]}
        m = is_muted(a, mutes)
        end = r["resolved_at"] or t
        out.append({
            "id": r["id"], "key": r["key"], "kind": r["kind"], "sev": r["severity"], "node": r["node"],
            "where": r["target"], "msg": r["message"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "resolved_at": r["resolved_at"], "duration": end - r["first_seen"], "flaps": r["flaps"],
            "flapping": r["flaps"] >= FLAP_QUIET - 1, "acked_by": r["acked_by"], "acked_at": r["acked_at"],
            "muted": bool(m), "muted_until": m["until"] if m else None,
            "status": "resolved" if r["resolved_at"] else "firing",
        })
    return out


def active_alerts() -> list[dict]:
    t = int(time.time())
    rows = st.store.db.q("SELECT * FROM alerts WHERE resolved_at IS NULL "
                         "ORDER BY CASE severity WHEN 'crit' THEN 0 ELSE 1 END, first_seen DESC")
    return _decorate(rows, t)


def _query(state: str, sev: str, q: str, days: int, limit: int) -> list[dict]:
    t = int(time.time())
    where, args = [], []
    if state == "active":
        where.append("resolved_at IS NULL")
    else:
        where.append("first_seen >= ? OR resolved_at IS NULL")
        args.append(t - max(1, min(days, 3650)) * 86400)
    if sev in SEVS:
        where.append("severity = ?")
        args.append(sev)
    if q:
        where.append("(target LIKE ? OR message LIKE ? OR kind LIKE ?)")
        args += [f"%{q}%"] * 3
    sql = ("SELECT * FROM alerts WHERE " + " AND ".join(f"({w})" for w in where) +
           " ORDER BY (resolved_at IS NULL) DESC, first_seen DESC LIMIT ?")
    return _decorate(st.store.db.q(sql, (*args, max(1, min(limit, 5000)))), t)


async def _mine(request: Request, rows: list[dict]) -> list[dict]:
    """Scoped users only see alerts about their own sites, tunnels and backends."""
    sc = scope(request)
    if sc.all:
        return rows
    await sites.prime_scope(sc)
    return [a for a in rows if sc.text_ok(a.get("where", ""))]


@router.get("/alerts")
async def list_alerts(request: Request, state: str = "active", sev: str = "", q: str = "", days: int = 7, limit: int = 500):
    return {"items": await _mine(request, _query(state, sev, q.strip()[:100], days, limit))}


@router.get("/alerts/summary")
async def summary(request: Request):
    act = await _mine(request, active_alerts())
    live = [a for a in act if not a["muted"]]
    return {"active": len(act), "unacked": sum(1 for a in live if not a["acked_by"]),
            "crit": sum(1 for a in live if a["sev"] == "crit" and not a["acked_by"]),
            "last_run": st.engine.last_run, "last_error": st.engine.last_error, "interval": st.s.alert_interval}


@router.post("/alerts/drift/accept")
async def drift_accept(request: Request, body: dict = Body(...)):
    """'Accept change' on a changed-outside-the-dashboard alert."""
    from . import history
    need(request, "operator")
    scope(request).need_all("Accepting a config change made outside the dashboard")
    where = str(body.get("where", ""))
    history.accept(st, where)
    audit(request, "config change accepted", where, True, "changed outside the dashboard; accepted as the known version")
    return {"ok": True}


@router.post("/alerts/{aid}/ack")
async def ack(request: Request, aid: int, body: dict = Body(default={})):
    need(request, "operator")
    row = st.store.db.one("SELECT * FROM alerts WHERE id=?", (aid,))
    if not row or not await _mine(request, [{"where": row["target"]}]):
        raise KeyError("alert not found")
    if body.get("ack", True):
        st.store.db.x("UPDATE alerts SET acked_by=?, acked_at=? WHERE id=?", (user(request)["username"], int(time.time()), aid))
    else:
        st.store.db.x("UPDATE alerts SET acked_by=NULL, acked_at=NULL WHERE id=?", (aid,))
    audit(request, "alert ack" if body.get("ack", True) else "alert unack", row["target"], True, row["message"])
    return {"ok": True}


@router.post("/alerts/check")
async def check_now(request: Request):
    need(request, "operator")
    return await st.engine.check_once()


@router.get("/alerts/export.csv")
async def export(request: Request, state: str = "history", sev: str = "", q: str = "", days: int = 30):
    rows = await _mine(request, _query(state, sev, q.strip()[:100], days, 5000))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "status", "target", "message", "started", "resolved", "duration_s", "flaps",
                "acked_by", "kind"])

    def cell(v):
        s = "" if v is None else str(v)
        return "'" + s if s[:1] in ("=", "+", "-", "@") else s   # no spreadsheet formula injection

    fmt = lambda ts: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""
    for r in rows:
        w.writerow([cell(x) for x in (r["id"], r["sev"], r["status"], r["where"], r["msg"], fmt(r["first_seen"]),
                                      fmt(r["resolved_at"]), r["duration"], r["flaps"], r["acked_by"], r["kind"])])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="gwconsole-alerts-{time.strftime("%Y%m%d")}.csv"'})


# ---- mutes ----------------------------------------------------------------------
async def _mute_ok(request: Request, match: str) -> bool:
    sc = scope(request)
    if sc.all:
        return True
    if match.startswith("node:"):
        return False
    row = st.store.db.one("SELECT target FROM alerts WHERE key=? ORDER BY id DESC LIMIT 1", (match,))
    return bool(row) and bool(await _mine(request, [{"where": row["target"]}]))


@router.get("/mutes")
async def mutes(request: Request):
    return {"items": [m for m in st.engine.mutes() if await _mute_ok(request, m.get("match", ""))]}


@router.post("/mutes")
async def add_mute(request: Request, body: dict = Body(...)):
    need(request, "operator")
    match = str(body.get("match", "")).strip()
    minutes = int(body.get("minutes", 60))
    if not 5 <= minutes <= 7 * 24 * 60:
        raise ValueError("mute for 5 minutes up to 7 days")
    if match.startswith("node:"):
        if not NAME_RE.match(match[5:]):
            raise ValueError("bad node name")
    elif not st.store.db.one("SELECT 1 FROM alerts WHERE key=?", (match,)) or not re.match(r"^[\w.]+\|", match):
        raise ValueError("unknown alert")
    if not await _mute_ok(request, match):
        from .scope import ScopeError
        raise ScopeError("you can only mute alerts about your own sites, tunnels and backends")
    t = int(time.time())
    reason = str(body.get("reason") or "")[:200]
    mid = st.store.db.x("INSERT INTO mutes (match, until, reason, created_by, created_at) VALUES (?,?,?,?,?)",
                        (match, t + minutes * 60, reason, user(request)["username"], t))
    audit(request, "mute", match, True, f"{minutes} min {reason}".strip())
    return {"ok": True, "id": mid}


@router.delete("/mutes/{mid}")
async def del_mute(request: Request, mid: int):
    need(request, "operator")
    row = st.store.db.one("SELECT * FROM mutes WHERE id=?", (mid,))
    if not row or not await _mute_ok(request, row["match"]):
        raise KeyError("mute not found")
    st.store.db.x("DELETE FROM mutes WHERE id=?", (mid,))
    audit(request, "unmute", row["match"], True)
    return {"ok": True}
