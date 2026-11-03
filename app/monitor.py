"""Monitoring: site checks, server health, watched services, certificates, history and the weekly summary.

A background loop (separate from the alert engine) that:
  * finds sites (sites.discover) and checks each one publicly (https://host through Cloudflare) and
    internally (the tunnel's origin service with the Host header, or a TCP connect);
  * reads CPU load, memory, disks, uptime and watched services on every node over SSH;
  * checks certificate expiry (HAProxy .pem files on the node, and the public certificate);
  * keeps 1-minute samples, rolls them up to 15-minute averages, and purges old history;
  * sends the weekly summary to Telegram/Discord.
The alert engine asks alerts() each round, so these alerts get mute/ack/notify like the others.
HAProxy request counters come from the engine's own snapshot through record_haproxy().
"""
from __future__ import annotations

import asyncio
import json
import logging
import shlex
import ssl
import time
from datetime import datetime, timedelta, timezone

import httpx

from . import sites
from .sshpool import NodeError
from .state import st

log = logging.getLogger("gwconsole.monitor")
TICK = 15
UNIT_OK = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@:-"


def tzinfo(cfg: dict):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(cfg.get("summary_tz") or "UTC")
    except Exception:
        return timezone.utc


def local_day(ts: float, cfg: dict) -> str:
    return datetime.fromtimestamp(ts, tzinfo(cfg)).strftime("%Y-%m-%d")


def valid_unit(u: str) -> bool:
    return 1 <= len(u) <= 128 and all(c in UNIT_OK for c in u) and not u.startswith("-")


# ------------------------------------------------------------------ samples
def add_samples(rows: list[tuple[str, int, float]]):
    if rows:
        with st.store.db.lock:
            st.store.db.conn.executemany(
                "INSERT INTO samples (series, ts, value) VALUES (?,?,?) "
                "ON CONFLICT(series, ts) DO UPDATE SET value=excluded.value", rows)


RANGES = {"1h": (3600, 60, "raw"), "6h": (21600, 300, "raw"), "24h": (86400, 600, "raw"),
          "7d": (604800, 3600, "15m"), "30d": (2592000, 14400, "15m")}


def series(names: list[str], rng: str = "24h", agg: str = "avg") -> dict[str, list]:
    """{name: [[ts, value], ...]} bucketed for charts. agg 'sum' for counters (requests per bucket)."""
    span, step, table = RANGES.get(rng, RANGES["24h"])
    since = int(time.time()) - span
    fn = "SUM" if agg == "sum" else "AVG"
    tbl = "samples" if table == "raw" else "samples_15m"
    if agg == "sum" and table == "15m":
        expr = "SUM(value * n)"
    else:
        expr = f"{fn}(value)"
    out = {}
    for n in names[:40]:
        rows = st.store.db.q(f"SELECT (ts/{step})*{step} AS t, {expr} AS v FROM {tbl} "
                             "WHERE series=? AND ts>=? GROUP BY t ORDER BY t", (n, since))
        out[n] = [[r["t"], round(r["v"], 2)] for r in rows]
    return out


def uptime(series_name: str, seconds: int) -> float | None:
    since = int(time.time()) - seconds
    tables = ["samples"] if seconds <= 172800 else ["samples_15m", "samples"]   # raw when no roll-up exists yet
    for tbl in tables:
        r = st.store.db.one(f"SELECT AVG(value) AS v, COUNT(*) AS c FROM {tbl} WHERE series=? AND ts>=?",
                            (series_name, since))
        if r and r["c"]:
            return round(r["v"] * 100, 2)
    return None


# ------------------------------------------------------------------ checks
async def http_check(client: httpx.AsyncClient, url: str, host: str | None, opts: dict) -> dict:
    t0 = time.perf_counter()
    try:
        r = await client.get(url, headers={"Host": host, "User-Agent": "gwconsole-monitor"} if host
                             else {"User-Agent": "gwconsole-monitor"})
    except httpx.HTTPError as e:
        msg = str(e) or type(e).__name__
        return {"ok": False, "code": None, "ms": None, "err": msg[:160]}
    ms = int((time.perf_counter() - t0) * 1000)
    exp = opts.get("expect")
    ok = (r.status_code == int(exp)) if exp else r.status_code < 500
    err = "" if ok else f"HTTP {r.status_code}"
    kw = opts.get("keyword")
    if ok and kw and kw not in r.text:
        ok, err = False, f"'{kw}' not on the page"
    return {"ok": ok, "code": r.status_code, "ms": ms, "err": err}


async def tcp_check(hostport: str) -> dict:
    scheme, ip, port = sites.split_service(hostport)
    if not ip or not port:
        return {"ok": False, "code": None, "ms": None, "err": "no address"}
    t0 = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 5)
        w.close()
        return {"ok": True, "code": "open", "ms": max(1, int((time.perf_counter() - t0) * 1000)), "err": ""}
    except (OSError, asyncio.TimeoutError) as e:
        return {"ok": False, "code": None, "ms": None, "err": (str(e) or "timed out")[:160]}


async def public_cert(host: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), 8)
        c = w.get_extra_info("peercert") or {}
        w.close()
        exp = ssl.cert_time_to_seconds(c["notAfter"])
        issuer = dict(x[0] for x in c.get("issuer", ())).get("organizationName", "")
        return {"not_after": int(exp), "days": int((exp - time.time()) // 86400), "issuer": issuer}
    except Exception as e:
        return {"error": (str(e) or type(e).__name__)[:160]}


HEALTH_SH = r"""
echo @@CORES; nproc 2>/dev/null
echo @@LOAD; cat /proc/loadavg
echo @@MEM; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo
echo @@DISK; df -P -k -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | tail -n +2
echo @@UP; cut -d' ' -f1 /proc/uptime
echo @@OS; ( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}" )
echo @@SVC
"""


def parse_health(text: str) -> dict:
    parts: dict[str, list[str]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            parts[cur] = []
        elif cur:
            parts[cur].append(line)
    h = {"cores": 1, "load": [0.0, 0.0, 0.0], "mem_pct": None, "mem_total": None, "disks": [], "fullest": None,
         "uptime": None, "os": "", "services": {}}
    try:
        h["cores"] = max(1, int((parts.get("CORES") or ["1"])[0]))
    except ValueError:
        pass
    try:
        h["load"] = [float(x) for x in (parts.get("LOAD") or ["0 0 0"])[0].split()[:3]]
    except (ValueError, IndexError):
        pass
    mem = {}
    for l in parts.get("MEM", []):
        k, _, v = l.partition(":")
        try:
            mem[k] = int(v.split()[0]) * 1024
        except (ValueError, IndexError):
            pass
    if mem.get("MemTotal"):
        h["mem_total"] = mem["MemTotal"]
        h["mem_pct"] = round(100 - mem.get("MemAvailable", 0) * 100 / mem["MemTotal"], 1)
    seen = set()
    for l in parts.get("DISK", []):
        f = l.split()
        if len(f) < 6 or not f[1].isdigit() or int(f[1]) == 0 or f[0] in seen:
            continue
        seen.add(f[0])
        mount = " ".join(f[5:])
        if mount.startswith(("/boot", "/snap", "/run", "/dev")):
            continue
        h["disks"].append({"mount": mount, "size": int(f[1]) * 1024, "pct": round(int(f[2]) * 100 / int(f[1]), 1)})
    if h["disks"]:
        h["fullest"] = max(h["disks"], key=lambda d: d["pct"])
    try:
        h["uptime"] = int(float((parts.get("UP") or ["0"])[0]))
    except ValueError:
        pass
    h["os"] = (parts.get("OS") or [""])[0].strip()
    for l in parts.get("SVC", []):
        u, _, s = l.strip().partition(" ")
        if u:
            h["services"][u] = s.strip() or "unknown"
    return h


# ------------------------------------------------------------------ the monitor
class Monitor:
    def __init__(self):
        self.task: asyncio.Task | None = None
        self.http: httpx.AsyncClient | None = None
        self.http_insecure: httpx.AsyncClient | None = None
        self.due = {"discover": 0.0, "sites": 0.0, "health": 0.0, "certs": 0.0, "roll": 0.0}
        self.last_run = 0
        self.last_error = ""
        self.discover_error = ""
        self.hp_prev: dict = {}
        self.hp_bucket: dict = {}
        self.hp_minute = 0
        self.load_high: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def _clients(self):
        if not self.http:
            self.http = httpx.AsyncClient(timeout=10, follow_redirects=False)
            # internal checks go straight to the origin, never through a proxy set in the environment
            self.http_insecure = httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False, trust_env=False)

    def start(self):
        self.task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self):
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
        for c in (self.http, self.http_insecure):
            if c:
                await c.aclose()

    async def _loop(self):
        await asyncio.sleep(5)
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
                log.exception("monitor round failed")
            await asyncio.sleep(TICK)

    async def tick(self, force: bool = False):
        async with self._lock:
            self._clients()
            cfg = st.store.monitor_cfg()
            now = time.time()
            if force or now >= self.due["discover"]:
                self.due["discover"] = now + 300
                await self.discover()
            if force or now >= self.due["sites"]:
                self.due["sites"] = now + cfg["check_every"]
                await self.check_sites(cfg)
            if force or now >= self.due["health"]:
                self.due["health"] = now + cfg["health_every"]
                await self.read_health(cfg)
            if force or now >= self.due["certs"]:
                self.due["certs"] = now + 3600
                await self.check_certs()
            if now >= self.due["roll"]:
                self.due["roll"] = now + 900
                self.rollup(cfg)
            await self.weekly(cfg)
            from . import traffic
            await traffic.loop_once()
            self.last_run = int(time.time())
            self.last_error = ""

    # ---------------------------------------------------------- sites
    async def discover(self):
        db = st.store.db
        try:
            found = await sites.discover()
            self.discover_error = ""
        except Exception as e:      # keep the last known list
            self.discover_error = str(e)
            return
        t = int(time.time())
        for s in found:
            row = db.one("SELECT source FROM checks WHERE host=?", (s["host"],))
            if row and row["source"] == "manual":
                continue
            if row:
                db.x("UPDATE checks SET kind=?, source=?, internal=?, route=?, seen_at=? WHERE host=?",
                     (s["kind"], s["source"], s["internal"], json.dumps({**s["route"], "tunnel": s["tunnel"],
                                                                         "path": s["path"]}), t, s["host"]))
            else:
                opts = {"public": s["source"] == "tunnel" and s["kind"] == "http"}
                db.x("INSERT INTO checks (host, kind, source, internal, route, opts, seen_at, created_at) "
                     "VALUES (?,?,?,?,?,?,?,?)",
                     (s["host"], s["kind"], s["source"], s["internal"],
                      json.dumps({**s["route"], "tunnel": s["tunnel"], "path": s["path"]}), json.dumps(opts), t, t))
        # hostnames gone from every tunnel and HAProxy rule for a day are dropped (unless excluded)
        db.x("DELETE FROM checks WHERE source != 'manual' AND excluded = 0 AND seen_at < ?", (t - 86400,))

    async def check_one(self, row: dict, cfg: dict) -> dict:
        opts = json.loads(row["opts"] or "{}")
        state = json.loads(row["state"] or "{}")
        host, kind = row["host"], row["kind"]
        path = opts.get("path") or "/"
        jobs = {}
        if kind == "http" and opts.get("public", True):
            jobs["pub"] = http_check(self.http, f"https://{host}{path}", None, opts)
        if row["internal"]:
            if kind == "tcp":
                jobs["int"] = tcp_check(row["internal"])
            else:
                base = row["internal"].rstrip("/")
                jobs["int"] = http_check(self.http_insecure, base + path, host, opts)
        res = dict(zip(jobs, await asyncio.gather(*jobs.values())))
        t = int(time.time()) // 60 * 60
        samples = []
        for side in ("pub", "int"):
            if side not in res:
                state.pop(side, None)
                continue
            r = res[side]
            prev = state.get(side) or {}
            r["fails"] = 0 if r["ok"] else prev.get("fails", 0) + 1
            r["slow"] = (prev.get("slow", 0) + 1) if r["ok"] and r["ms"] and r["ms"] > int(opts.get("slow_ms") or cfg["slow_ms"]) else 0
            r["at"] = int(time.time())
            state[side] = r
            samples.append((f"site.{side}.up:{host}", t, 1.0 if r["ok"] else 0.0))
            if r["ms"] is not None:
                samples.append((f"site.{side}.ms:{host}", t, float(r["ms"])))
        prim = state.get("pub") or state.get("int")
        if not prim:
            status = "unknown"
        elif prim["fails"] >= int(cfg["down_after"]):
            status = "down"
        elif not prim["ok"]:
            status = "failing"
        elif prim["slow"] >= 3:
            status = "slow"
        else:
            status = "up"
        if status == "down" and state.get("status") != "down":
            state["down_since"] = int(time.time())
        elif status != "down":
            state.pop("down_since", None)
        state["status"] = status
        add_samples(samples)
        st.store.db.x("UPDATE checks SET state=? WHERE host=?", (json.dumps(state), host))
        return state

    async def check_sites(self, cfg: dict, only: str | None = None):
        rows = st.store.db.q("SELECT * FROM checks WHERE excluded=0" + (" AND host=?" if only else ""),
                             (only,) if only else ())
        sem = asyncio.Semaphore(10)

        async def one(r):
            async with sem:
                try:
                    await self.check_one(r, cfg)
                except Exception as e:
                    log.warning("check %s failed: %s", r["host"], e)
        await asyncio.gather(*(one(r) for r in rows))

    # ---------------------------------------------------------- servers
    def watched(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for r in st.store.db.q("SELECT node, unit FROM services ORDER BY unit"):
            out.setdefault(r["node"], []).append(r["unit"])
        return out

    async def read_health(self, cfg: dict):
        watched = self.watched()
        t = int(time.time())
        tm = t // 60 * 60

        async def one(n):
            units = [u for u in watched.get(n.name, []) if valid_unit(u)]
            cmd = HEALTH_SH + "".join(f"printf '%s %s\\n' {shlex.quote(u)} \"$(systemctl is-active {shlex.quote(u)} 2>/dev/null)\"\n"
                                      for u in units)
            try:
                r = await st.pool.run(n, cmd, root=False, timeout=20)
                h = parse_health(r.out)
                h["error"] = None
            except (NodeError, OSError) as e:
                old = st.store.db.one("SELECT data FROM health WHERE node=?", (n.name,))
                h = json.loads(old["data"]) if old else {}
                h["error"] = str(e)
                st.store.db.x("INSERT INTO health (node, data, at) VALUES (?,?,?) ON CONFLICT(node) DO UPDATE SET "
                              "data=excluded.data", (n.name, json.dumps(h), 0))
                return
            st.store.db.x("INSERT INTO health (node, data, at) VALUES (?,?,?) ON CONFLICT(node) DO UPDATE SET "
                          "data=excluded.data, at=excluded.at", (n.name, json.dumps(h), t))
            rows = [(f"srv.load:{n.name}", tm, h["load"][0])]
            if h["mem_pct"] is not None:
                rows.append((f"srv.mem:{n.name}", tm, h["mem_pct"]))
            if h["fullest"]:
                rows.append((f"srv.disk:{n.name}", tm, h["fullest"]["pct"]))
            add_samples(rows)
            if h["load"][0] > float(cfg["load_factor"]) * h["cores"]:
                self.load_high.setdefault(n.name, t)
            else:
                self.load_high.pop(n.name, None)

        await asyncio.gather(*(one(n) for n in st.s.all_nodes()))

    # ---------------------------------------------------------- certificates
    async def check_certs(self):
        out = []
        models = await sites.hp_models()
        for n in st.s.haproxy_nodes:
            paths = sorted({b["crt"] for fe in models.get(n.name, {}).get("frontends", [])
                            for b in fe.get("binds") or [] if b.get("crt")})
            if not paths:
                continue
            q = " ".join(shlex.quote(p) for p in paths)
            cmd = (f"for p in {q}; do if [ -d \"$p\" ]; then set -- \"$p\"/*.pem \"$p\"/*.crt; else set -- \"$p\"; fi; "
                   "for f in \"$@\"; do [ -f \"$f\" ] || continue; echo \"@@FILE $f\"; "
                   "openssl x509 -noout -enddate -subject -in \"$f\" 2>&1 | head -2; done; done")
            try:
                r = await st.pool.run(n, cmd, timeout=30)
            except (NodeError, OSError):
                continue
            cur = None
            for line in r.out.splitlines():
                if line.startswith("@@FILE "):
                    cur = {"node": n.name, "file": line[7:].strip(), "subject": ""}
                    out.append(cur)
                elif cur and line.startswith("notAfter="):
                    try:
                        exp = ssl.cert_time_to_seconds(line[9:].strip())
                        cur.update(not_after=int(exp), days=int((exp - time.time()) // 86400))
                    except ValueError:
                        pass
                elif cur and line.startswith("subject"):
                    cur["subject"] = line.split("CN", 1)[-1].lstrip(" =").strip() if "CN" in line else line[8:].strip()
        st.store.put("certs", {"at": int(time.time()), "items": [c for c in out if "days" in c]})
        for row in st.store.db.q("SELECT host, state, opts FROM checks WHERE excluded=0 AND kind='http'"):
            if not json.loads(row["opts"] or "{}").get("public", True):
                continue
            state = json.loads(row["state"] or "{}")
            state["cert"] = await public_cert(row["host"])
            st.store.db.x("UPDATE checks SET state=? WHERE host=?", (json.dumps(state), row["host"]))

    # ---------------------------------------------------------- HAProxy counters (from the alert engine)
    def record_haproxy(self, hp: list[dict]):
        """Turn HAProxy's ever-growing counters into per-minute requests / 5xx / bytes and daily totals."""
        cfg = st.store.monitor_cfg()
        now = int(time.time())
        minute = now // 60 * 60
        if self.hp_minute and minute != self.hp_minute:
            self._flush_hp(cfg)
        self.hp_minute = minute
        for n in hp:
            if n.get("error") or n.get("stats_error"):
                continue
            conns = int((n.get("info") or {}).get("CurrConns") or 0)
            b = self.hp_bucket.setdefault((n["node"], "conn"), {"conn": 0})
            b["conn"] = max(b["conn"], conns)
            pxs = [("fe", f) for f in n.get("frontends", [])] + [("be", b) for b in n.get("backends", [])]
            for kind, p in pxs:
                key = (n["node"], f"{kind}:{p['name']}")
                req = p.get("req_tot") if p.get("mode") == "http" and p.get("req_tot") is not None else p.get("stot")
                cur = {"req": req or 0, "s4xx": p.get("hrsp_4xx") or 0, "s5xx": p.get("hrsp_5xx") or 0,
                       "bytes": (p.get("bin") or 0) + (p.get("bout") or 0)}
                prev = self.hp_prev.get(key)
                self.hp_prev[key] = cur
                if prev is None:
                    continue
                acc = self.hp_bucket.setdefault(key, {"req": 0, "s4xx": 0, "s5xx": 0, "bytes": 0})
                for k, v in cur.items():
                    d = v - prev[k]
                    acc[k] += d if d >= 0 else v      # counter reset (reload/restart): count from zero
        return True

    def _flush_hp(self, cfg: dict):
        t = self.hp_minute
        day = local_day(t, cfg)
        rows = []
        db = st.store.db
        for (node, name), acc in self.hp_bucket.items():
            if name == "conn":
                rows.append((f"hp.conn:{node}", t, float(acc["conn"])))
                continue
            rows += [(f"hp.req:{node}/{name}", t, float(acc["req"])), (f"hp.5xx:{node}/{name}", t, float(acc["s5xx"])),
                     (f"hp.bytes:{node}/{name}", t, float(acc["bytes"]))]
            db.x("INSERT INTO traffic_daily (day, source, name, requests, bytes, s4xx, s5xx) VALUES (?,?,?,?,?,?,?) "
                 "ON CONFLICT(day, source, name) DO UPDATE SET requests=requests+excluded.requests, "
                 "bytes=bytes+excluded.bytes, s4xx=s4xx+excluded.s4xx, s5xx=s5xx+excluded.s5xx",
                 (day, "hp", f"{node}/{name}", acc["req"], acc["bytes"], acc["s4xx"], acc["s5xx"]))
        add_samples(rows)
        self.hp_bucket = {}

    # ---------------------------------------------------------- history
    def rollup(self, cfg: dict):
        db = st.store.db
        now = int(time.time())
        end = now // 900 * 900
        db.x("INSERT INTO samples_15m (series, ts, value, n) SELECT series, (ts/900)*900, AVG(value), COUNT(*) "
             "FROM samples WHERE ts >= ? AND ts < ? GROUP BY series, ts/900 "
             "ON CONFLICT(series, ts) DO UPDATE SET value=excluded.value, n=excluded.n", (end - 7200, end))
        db.x("DELETE FROM samples WHERE ts < ?", (now - int(cfg["keep_raw_hours"]) * 3600,))
        db.x("DELETE FROM samples_15m WHERE ts < ?", (now - int(cfg["keep_15m_days"]) * 86400,))
        db.x("DELETE FROM traffic_daily WHERE day < ?", (local_day(now - int(cfg["keep_daily_days"]) * 86400, cfg),))

    # ---------------------------------------------------------- alerts
    def alerts(self) -> tuple[list[dict], set[str]]:
        cfg = st.store.monitor_cfg()
        out: list[dict] = []
        unknown: set[str] = set()
        now = int(time.time())

        def add(sev, kind, node, target, msg, sub=""):
            out.append({"key": f"{kind}|{target}{'|' + sub if sub else ''}", "kind": kind, "sev": sev,
                        "node": node, "where": target, "msg": msg})

        for r in st.store.db.q("SELECT host, state, opts FROM checks WHERE excluded=0"):
            s = json.loads(r["state"] or "{}")
            p = s.get("pub") or s.get("int") or {}
            side = "public" if s.get("pub") else "internal"
            if s.get("status") == "down":
                add("crit", "site.down", "", r["host"],
                    f"site down ({side}): {p.get('err') or 'no answer'} — {p.get('fails')} checks in a row")
            elif s.get("status") == "slow":
                add("warn", "site.slow", "", r["host"], f"site slow ({side}): {p.get('ms')} ms")
            c = s.get("cert") or {}
            if "days" in c and c["days"] <= int(cfg["cert_warn"]):
                add("crit" if c["days"] <= int(cfg["cert_crit"]) else "warn", "cert.expiring", "", r["host"],
                    f"public certificate expires in {c['days']} days")
        for c in (st.store.get("certs", {}) or {}).get("items", []):
            if c["days"] <= int(cfg["cert_warn"]):
                add("crit" if c["days"] <= int(cfg["cert_crit"]) else "warn", "cert.expiring", c["node"],
                    f"{c['node']} / {c['file']}", f"certificate {c.get('subject') or ''} expires in {c['days']} days".replace("  ", " "))
        kinds = {n.name: k for k, lst in (("haproxy", st.s.haproxy_nodes), ("cloudflared", st.s.cloudflared_nodes),
                                          ("server", st.s.server_nodes)) for n in lst}
        watched = self.watched()
        for r in st.store.db.q("SELECT * FROM health"):
            node = r["node"]
            if node not in kinds:
                continue
            h = json.loads(r["data"])
            if h.get("error") or now - r["at"] > max(300, 5 * int(cfg["health_every"])):
                unknown.add(node)
                if kinds[node] == "server" and h.get("error"):
                    add("crit", "node.unreachable", node, node, h["error"])
                continue
            f = h.get("fullest")
            if f and f["pct"] >= cfg["disk_warn"]:
                add("crit" if f["pct"] >= cfg["disk_crit"] else "warn", "srv.disk", node, node,
                    f"disk {f['mount']} {f['pct']:.0f}% full")
            if h.get("mem_pct") is not None and h["mem_pct"] >= cfg["mem_crit"]:
                add("crit", "srv.mem", node, node, f"memory {h['mem_pct']:.0f}% used")
            since = self.load_high.get(node)
            if since and now - since >= int(cfg["load_minutes"]) * 60:
                add("warn", "srv.load", node, node,
                    f"CPU load {h['load'][0]:.2f} on {h['cores']} cores for {(now - since) // 60} min")
            for u in watched.get(node, []):
                state = h.get("services", {}).get(u)
                if state and state not in ("active", "activating", "reloading"):
                    add("crit", "svc.stopped", node, f"{node} / {u}", f"service {u} is {state}")
        # backend 5xx share over the last N minutes
        mins = int(cfg["err5xx_minutes"])
        rows = st.store.db.q("SELECT series, SUM(value) AS v FROM samples WHERE ts >= ? AND "
                             "(series LIKE 'hp.req:%/be:%' OR series LIKE 'hp.5xx:%/be:%') GROUP BY series",
                             (now - mins * 60 - 60,))
        req = {r["series"][7:]: r["v"] for r in rows if r["series"].startswith("hp.req:")}
        for r in rows:
            if not r["series"].startswith("hp.5xx:"):
                continue
            name = r["series"][7:]
            total = req.get(name) or 0
            if total >= int(cfg["err5xx_min"]) and r["v"] * 100 / total > float(cfg["err5xx_pct"]):
                node, be = name.split("/be:", 1)
                add("warn", "hp.5xx", node, f"{node} / {be}",
                    f"{r['v'] * 100 / total:.1f}% of {int(total)} requests got a 5xx in the last {mins} min")
        return out, unknown

    # ---------------------------------------------------------- weekly summary
    async def weekly(self, cfg: dict, force: bool = False) -> str | None:
        if not force and not cfg["summary_enabled"]:
            return None
        tz = tzinfo(cfg)
        now = datetime.now(tz)
        week = now.strftime("%G-W%V")
        if not force:
            hh, mm = (int(x) for x in cfg["summary_time"].split(":"))
            if now.weekday() != int(cfg["summary_day"]) or (now.hour, now.minute) < (hh, mm):
                return None
            if st.store.get("summary_sent") == week:
                return None
            st.store.put("summary_sent", week)
        text = self.summary_text(cfg)
        chans = [c for c in ("telegram", "discord") if cfg.get(f"summary_{c}")]
        await st.engine.announce(text, channels=chans, icon="📊")
        return text

    def summary_text(self, cfg: dict) -> str:
        tz = tzinfo(cfg)
        end = datetime.now(tz)
        start = end - timedelta(days=7)
        db = st.store.db
        lines = [f"Weekly summary · {start:%-d %b} – {end:%-d %b %Y}"]
        ups = []
        for r in db.q("SELECT host, opts FROM checks WHERE excluded=0 ORDER BY host"):
            side = "pub" if json.loads(r["opts"] or "{}").get("public", True) else "int"
            u = uptime(f"site.{side}.up:{r['host']}", 7 * 86400)
            if u is None:
                u = uptime(f"site.{'int' if side == 'pub' else 'pub'}.up:{r['host']}", 7 * 86400)
            if u is not None:
                ups.append((u, r["host"]))
        if ups:
            ups.sort()
            worst = [f"{h} {u:.2f}%" for u, h in ups if u < 100][:5]
            lines.append(f"Uptime: {sum(1 for u, _ in ups if u >= 100)} of {len(ups)} sites at 100%"
                         + (f"; lowest: {', '.join(worst)}" if worst else ""))
        inc = db.q("SELECT target, first_seen, COALESCE(resolved_at, ?) AS end FROM alerts "
                   "WHERE kind='site.down' AND first_seen >= ?", (int(time.time()), int(start.timestamp())))
        if inc:
            longest = max(inc, key=lambda r: r["end"] - r["first_seen"])
            lines.append(f"Incidents: {len(inc)} site outage(s); longest {longest['target']} "
                         f"{max(1, (longest['end'] - longest['first_seen']) // 60)} min")
        else:
            lines.append("Incidents: none")
        d0 = start.strftime("%Y-%m-%d")
        top = db.q("SELECT name, SUM(requests) AS r FROM traffic_daily WHERE source='cf' AND day > ? "
                   "GROUP BY name ORDER BY r DESC LIMIT 3", (d0,))
        if not top:
            top = db.q("SELECT name, SUM(requests) AS r FROM traffic_daily WHERE source='hp' AND day > ? "
                       "AND name LIKE '%/fe:%' GROUP BY name ORDER BY r DESC LIMIT 3", (d0,))
        if top:
            lines.append("Busiest: " + ", ".join(f"{r['name'].replace('/fe:', ' / ')} {human(r['r'])}" for r in top))
        bad = db.q("SELECT name, SUM(requests) AS r, SUM(s5xx) AS e FROM traffic_daily WHERE source='hp' AND day > ? "
                   "AND name LIKE '%/be:%' GROUP BY name HAVING r >= 100 ORDER BY 1.0*e/r DESC LIMIT 1", (d0,))
        if bad and bad[0]["e"]:
            b = bad[0]
            lines.append(f"Most 5xx: {b['name'].replace('/be:', ' / ')} {b['e'] * 100 / b['r']:.2f}% of {human(b['r'])}")
        full = []
        for r in db.q("SELECT node, data FROM health"):
            f = json.loads(r["data"]).get("fullest")
            if f and f["pct"] >= cfg["disk_warn"] - 10:
                full.append(f"{r['node']} {f['mount']} {f['pct']:.0f}%")
        if full:
            lines.append("Disks filling up: " + ", ".join(full))
        if st.s.dashboard_url:
            lines.append(f"{st.s.dashboard_url}/#/monitoring")
        return "\n".join(lines)


def human(n: float) -> str:
    n = float(n or 0)
    for unit, d in (("M", 1e6), ("k", 1e3)):
        if n >= d:
            return f"{n / d:.1f}{unit}"
    return str(int(n))
