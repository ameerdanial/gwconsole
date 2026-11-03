"""Traffic: how many requests each site and HAProxy frontend/backend gets, kept for a year.

Two sources, both stored per day in the traffic_daily table:
  * Cloudflare (GraphQL Analytics API): per hostname — requests, bandwidth, visits, cached share,
    4xx/5xx, top countries — and per zone — unique visitors and threats blocked. Fetched every
    30 minutes for today and yesterday; the first run back-fills what Cloudflare still has.
  * HAProxy: per-minute counter deltas from the alert engine (monitor.record_haproxy), so totals
    survive HAProxy reloads and restarts and include internal traffic and TCP services.
report() builds the Traffic page for a range (today / 7 days / 30 days / 12 months).
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from .cfapi import CFError
from .monitor import local_day, tzinfo
from .state import st

log = logging.getLogger("gwconsole.traffic")
REFRESH = 1800
CACHED = {"hit", "stale", "updating", "revalidated"}

Q_HOSTS = """query($zone: string!, $since: Time!, $until: Time!) { viewer { zones(filter: {zoneTag: $zone}) {
  hosts: httpRequestsAdaptiveGroups(limit: 5000, filter: {datetime_geq: $since, datetime_lt: $until, requestSource: "eyeball"}) {
    count sum { edgeResponseBytes visits } dimensions { clientRequestHTTPHost edgeResponseStatus cacheStatus } }
  countries: httpRequestsAdaptiveGroups(limit: 5000, filter: {datetime_geq: $since, datetime_lt: $until, requestSource: "eyeball"}) {
    count dimensions { clientRequestHTTPHost clientCountryName } } } } }"""

Q_HOURS = """query($zone: string!, $since: Time!, $until: Time!) { viewer { zones(filter: {zoneTag: $zone}) {
  hours: httpRequestsAdaptiveGroups(limit: 5000, filter: {datetime_geq: $since, datetime_lt: $until, requestSource: "eyeball"}) {
    count dimensions { clientRequestHTTPHost datetimeHour } } } } }"""

Q_ZONE = """query($zone: string!, $since: Date!, $until: Date!) { viewer { zones(filter: {zoneTag: $zone}) {
  days: httpRequests1dGroups(limit: 400, filter: {date_geq: $since, date_leq: $until}, orderBy: [date_ASC]) {
    dimensions { date }
    sum { requests bytes cachedRequests threats
          countryMap { clientCountryName requests } responseStatusMap { edgeResponseStatus requests } }
    uniq { uniques } } } } }"""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _day_bounds(day: str, cfg: dict) -> tuple[str, str]:
    tz = tzinfo(cfg)
    start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=tz)
    end = min(start + timedelta(days=1), datetime.now(timezone.utc))
    return _iso(start), _iso(end)


def _put(day, source, name, requests=0, bytes_=0, visitors=0, cached=0, threats=0, s4xx=0, s5xx=0, extra=None):
    st.store.db.x(
        "INSERT INTO traffic_daily (day, source, name, requests, bytes, visitors, cached, threats, s4xx, s5xx, extra) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(day, source, name) DO UPDATE SET requests=excluded.requests, "
        "bytes=excluded.bytes, visitors=excluded.visitors, cached=excluded.cached, threats=excluded.threats, "
        "s4xx=excluded.s4xx, s5xx=excluded.s5xx, extra=excluded.extra",
        (day, source, name, int(requests), int(bytes_), int(visitors), int(cached), int(threats), int(s4xx), int(s5xx),
         json.dumps(extra or {})))


def _top(d: dict, n: int = 5) -> dict:
    return dict(sorted(d.items(), key=lambda kv: -kv[1])[:n])


class Collector:
    def __init__(self):
        self.next = 0.0
        self.hours_cache: dict = {}

    async def maybe_refresh(self, force: bool = False):
        if not force and time.time() < self.next:
            return
        self.next = time.time() + REFRESH
        await self.refresh()

    async def refresh(self):
        cfg = st.store.monitor_cfg()
        status = {"at": int(time.time()), "errors": {}, "zones": 0}
        for acc in st.s.cf_accounts.values():
            try:
                zones = await st.cf.zones(acc)
            except (CFError, httpx.HTTPError) as e:
                status["errors"][acc.name] = str(e)
                continue
            for z in zones:
                try:
                    await self.zone(acc, z, cfg)
                    status["zones"] += 1
                except (CFError, httpx.HTTPError) as e:
                    status["errors"][acc.name] = str(e)
                    break           # same token for every zone: no point trying the rest
        st.store.put("traffic_status", status)

    async def zone(self, acc, z: dict, cfg: dict):
        db = st.store.db
        have = db.one("SELECT 1 FROM traffic_daily WHERE source='cfzone' AND name=? LIMIT 1", (z["name"],))
        today = local_day(time.time(), cfg)
        back = 2 if have else 8
        days = [local_day(time.time() - i * 86400, cfg) for i in range(back)]
        for day in days:
            since, until = _day_bounds(day, cfg)
            d = await st.cf.graphql(acc, Q_HOSTS, {"zone": z["id"], "since": since, "until": until})
            self.store_hosts(day, d)
        # zone totals (UTC days): visitors and threats only exist here
        span = 2 if have else 30
        since = (datetime.now(timezone.utc) - timedelta(days=span)).strftime("%Y-%m-%d")
        d = await st.cf.graphql(acc, Q_ZONE, {"zone": z["id"], "since": since, "until": today})
        self.store_zone(z["name"], d)

    @staticmethod
    def store_hosts(day: str, data: dict):
        zs = (data.get("viewer") or {}).get("zones") or []
        if not zs:
            return
        agg: dict[str, dict] = {}
        for g in zs[0].get("hosts") or []:
            dm = g.get("dimensions") or {}
            h = (dm.get("clientRequestHTTPHost") or "").lower()
            if not h:
                continue
            a = agg.setdefault(h, {"requests": 0, "bytes": 0, "visits": 0, "cached": 0, "s4xx": 0, "s5xx": 0,
                                   "countries": {}})
            c = int(g.get("count") or 0)
            sm = g.get("sum") or {}
            a["requests"] += c
            a["bytes"] += int(sm.get("edgeResponseBytes") or 0)
            a["visits"] += int(sm.get("visits") or 0)
            if (dm.get("cacheStatus") or "").lower() in CACHED:
                a["cached"] += c
            code = int(dm.get("edgeResponseStatus") or 0)
            if 400 <= code < 500:
                a["s4xx"] += c
            elif code >= 500:
                a["s5xx"] += c
        for g in zs[0].get("countries") or []:
            dm = g.get("dimensions") or {}
            h = (dm.get("clientRequestHTTPHost") or "").lower()
            cc = dm.get("clientCountryName") or ""
            if h in agg and cc:
                agg[h]["countries"][cc] = agg[h]["countries"].get(cc, 0) + int(g.get("count") or 0)
        for h, a in agg.items():
            _put(day, "cf", h, a["requests"], a["bytes"], a["visits"], a["cached"], 0, a["s4xx"], a["s5xx"],
                 {"countries": _top(a["countries"])})

    @staticmethod
    def store_zone(name: str, data: dict):
        zs = (data.get("viewer") or {}).get("zones") or []
        if not zs:
            return
        for g in zs[0].get("days") or []:
            sm = g.get("sum") or {}
            s4 = sum(int(x.get("requests") or 0) for x in sm.get("responseStatusMap") or []
                     if 400 <= int(x.get("edgeResponseStatus") or 0) < 500)
            s5 = sum(int(x.get("requests") or 0) for x in sm.get("responseStatusMap") or []
                     if int(x.get("edgeResponseStatus") or 0) >= 500)
            cc = {x["clientCountryName"]: int(x.get("requests") or 0) for x in sm.get("countryMap") or []
                  if x.get("clientCountryName")}
            _put(g["dimensions"]["date"], "cfzone", name, sm.get("requests") or 0, sm.get("bytes") or 0,
                 (g.get("uniq") or {}).get("uniques") or 0, sm.get("cachedRequests") or 0, sm.get("threats") or 0,
                 s4, s5, {"countries": _top(cc)})

    async def today_hours(self) -> dict[str, list[int]]:
        """host → 24 hourly request counts for today (live from Cloudflare, cached 5 minutes)."""
        cfg = st.store.monitor_cfg()
        day = local_day(time.time(), cfg)
        c = self.hours_cache
        if c.get("day") == day and time.time() - c.get("at", 0) < 300:
            return c["data"]
        since, until = _day_bounds(day, cfg)
        tz = tzinfo(cfg)
        out: dict[str, list[int]] = {}
        for acc in st.s.cf_accounts.values():
            try:
                for z in await st.cf.zones(acc):
                    d = await st.cf.graphql(acc, Q_HOURS, {"zone": z["id"], "since": since, "until": until})
                    for g in ((d.get("viewer") or {}).get("zones") or [{}])[0].get("hours") or []:
                        dm = g.get("dimensions") or {}
                        h = (dm.get("clientRequestHTTPHost") or "").lower()
                        try:
                            hr = datetime.strptime(dm["datetimeHour"], "%Y-%m-%dT%H:%M:%SZ").replace(
                                tzinfo=timezone.utc).astimezone(tz).hour
                        except (KeyError, ValueError):
                            continue
                        out.setdefault(h, [0] * 24)[hr] += int(g.get("count") or 0)
            except (CFError, httpx.HTTPError):
                continue
        c.update(day=day, at=time.time(), data=out)
        return out


collector = Collector()


# ---------------------------------------------------------------- the Traffic page
RANGE_DAYS = {"today": 1, "7d": 7, "30d": 30, "12m": 365}


def _days(n: int, offset: int, cfg: dict) -> list[str]:
    return [local_day(time.time() - (i + offset) * 86400, cfg) for i in range(n)][::-1]


def _sum(rows: list[dict], keys=("requests", "bytes", "visitors", "cached", "threats", "s4xx", "s5xx")) -> dict:
    return {k: sum(int(r[k] or 0) for r in rows) for k in keys}


def _bucket(day: str, rng: str) -> str:
    return day[:7] if rng == "12m" else day


def _group(rows: list[dict], days: list[str], rng: str) -> tuple[list[dict], list[str]]:
    """Per-name totals with a per-day (or per-month) series for sparklines, biggest first."""
    labels = list(dict.fromkeys(_bucket(d, rng) for d in days))
    by: dict[str, dict] = {}
    for r in rows:
        g = by.setdefault(r["name"], {"name": r["name"], "rows": [], "series": dict.fromkeys(labels, 0),
                                      "countries": {}})
        g["rows"].append(r)
        g["series"][_bucket(r["day"], rng)] = g["series"].get(_bucket(r["day"], rng), 0) + int(r["requests"])
        for cc, n in json.loads(r["extra"] or "{}").get("countries", {}).items():
            g["countries"][cc] = g["countries"].get(cc, 0) + n
    out = []
    for g in by.values():
        t = _sum(g["rows"])
        out.append({"name": g["name"], **t, "series": [g["series"][k] for k in labels],
                    "countries": list(_top(g["countries"], 3).keys())})
    return sorted(out, key=lambda x: -x["requests"]), labels


def _stack(groups: list[dict], labels: list[str], n: int = 3) -> dict:
    top = groups[:n]
    other = [sum(g["series"][i] for g in groups[n:]) for i in range(len(labels))]
    series = [{"name": g["name"], "data": g["series"]} for g in top]
    if any(other):
        series.append({"name": "other", "data": other})
    return {"labels": labels, "series": series}


def _delta(cur: int, prev: int) -> float | None:
    return None if not prev else round((cur - prev) * 100 / prev, 1)


def _busiest_hour(name: str, days: int, cfg: dict) -> int | None:
    since = int(time.time()) - days * 86400
    tbl, w = ("samples", "value") if days <= 2 else ("samples_15m", "value * n")
    rows = st.store.db.q(f"SELECT ts, {w} AS v FROM {tbl} WHERE series=? AND ts>=?", (f"hp.req:{name}", since))
    if not rows and tbl != "samples":         # no roll-up yet: use the 1-minute samples
        rows = st.store.db.q("SELECT ts, value AS v FROM samples WHERE series=? AND ts>=?", (f"hp.req:{name}", since))
    if not rows:
        return None
    tz = tzinfo(cfg)
    hours = [0.0] * 24
    for r in rows:
        hours[datetime.fromtimestamp(r["ts"], tz).hour] += r["v"]
    return max(range(24), key=lambda h: hours[h]) if any(hours) else None


async def report(rng: str) -> dict:
    if rng not in RANGE_DAYS:
        rng = "7d"
    cfg = st.store.monitor_cfg()
    n = RANGE_DAYS[rng]
    days, prev_days = _days(n, 0, cfg), _days(n, n, cfg)
    db = st.store.db

    def rows(source, ds):
        q = ",".join("?" * len(ds))
        return db.q(f"SELECT * FROM traffic_daily WHERE source=? AND day IN ({q})", (source, *ds))

    # Cloudflare -------------------------------------------------------
    hosts, labels = _group(rows("cf", days), days, rng)
    zone_now, zone_prev = _sum(rows("cfzone", days)), _sum(rows("cfzone", prev_days))
    host_now, host_prev = _sum(rows("cf", days)), _sum(rows("cf", prev_days))
    base, basep = (zone_now, zone_prev) if zone_now["requests"] else (host_now, host_prev)
    if rng == "today":
        hrs = await collector.today_hours()
        for h in hosts:
            h["series"] = hrs.get(h["name"], [0] * 24)
        labels = [f"{i:02d}:00" for i in range(24)]
    cf = {
        "kpi": {k: {"value": base[k], "delta": _delta(base[k], basep[k])} for k in ("requests", "bytes", "threats")},
        "hosts": hosts, "chart": _stack(hosts, labels),
        "status": st.store.get("traffic_status", {}) or {}, "accounts": len(st.s.cf_accounts),
    }
    cf["kpi"]["visitors"] = {"value": zone_now["visitors"], "delta": _delta(zone_now["visitors"], zone_prev["visitors"])}
    cr = lambda d: round(d["cached"] * 100 / d["requests"], 1) if d["requests"] else None
    cf["kpi"]["cached"] = {"value": cr(base), "delta": (round(cr(base) - cr(basep), 1)
                                                        if cr(base) is not None and cr(basep) is not None else None)}
    # HAProxy ----------------------------------------------------------
    hp_rows = rows("hp", days)
    groups, hlabels = _group(hp_rows, days, rng)
    fes = [g for g in groups if "/fe:" in g["name"]]
    bes = [g for g in groups if "/be:" in g["name"]]
    for g in fes + bes:
        g["busiest"] = _busiest_hour(g["name"], min(n, 30), cfg)
    if rng == "today":
        hours = {}
        tz = tzinfo(cfg)
        start = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        for g in fes:
            arr = [0] * 24
            for r in db.q("SELECT ts, value FROM samples WHERE series=? AND ts>=?", (f"hp.req:{g['name']}", int(start))):
                arr[datetime.fromtimestamp(r["ts"], tz).hour] += int(r["value"])
            hours[g["name"]] = arr
            g["series"] = arr
        hlabels = [f"{i:02d}:00" for i in range(24)]
    fe_now = _sum([r for r in hp_rows if "/fe:" in r["name"]])
    fe_prev = _sum([r for r in rows("hp", prev_days) if "/fe:" in r["name"]])
    be_now = _sum([r for r in hp_rows if "/be:" in r["name"]])
    peak = db.one("SELECT MAX(value) AS v FROM samples WHERE series LIKE 'hp.conn:%' AND ts >= ?",
                  (int(time.time()) - min(n, 2) * 86400,))
    hp = {
        "kpi": {"requests": {"value": fe_now["requests"], "delta": _delta(fe_now["requests"], fe_prev["requests"])},
                "bytes": {"value": fe_now["bytes"], "delta": _delta(fe_now["bytes"], fe_prev["bytes"])},
                "err5xx": {"value": round(be_now["s5xx"] * 100 / be_now["requests"], 2) if be_now["requests"] else None},
                "peak_conns": {"value": int(peak["v"]) if peak and peak["v"] is not None else None}},
        "frontends": fes, "backends": bes, "chart": _stack(fes, hlabels),
    }
    return {"range": rng, "days": [days[0], days[-1]], "tz": cfg["summary_tz"], "cf": cf, "hp": hp}


def csv_rows(rep: dict, tab: str) -> list[list]:
    if tab == "hp":
        out = [["kind", "name", "requests", "bytes", "4xx", "5xx", "busiest_hour"]]
        for kind in ("frontends", "backends"):
            for g in rep["hp"][kind]:
                out.append([kind[:-1], g["name"], g["requests"], g["bytes"], g["s4xx"], g["s5xx"],
                            "" if g.get("busiest") is None else f"{g['busiest']:02d}:00"])
        return out
    out = [["hostname", "requests", "visits", "bytes", "cached_requests", "4xx", "5xx", "top_countries"]]
    for g in rep["cf"]["hosts"]:
        out.append([g["name"], g["requests"], g["visitors"], g["bytes"], g["cached"], g["s4xx"], g["s5xx"],
                    " ".join(g["countries"])])
    return out


async def loop_once():
    try:
        if st.s.cf_accounts:
            await collector.maybe_refresh()
    except Exception as e:     # never break the monitor loop
        log.warning("traffic refresh failed: %s", e)

