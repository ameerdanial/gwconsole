"""Background alert engine.

Every `alert_interval` seconds it collects live state, evaluates the alert rules
(collect.build_alerts) and keeps each alert's lifecycle in the database:

  firing  -> resolved   after it has been absent for RESOLVE_AFTER rounds in a row
  resolved -> firing    again within FLAP_WINDOW: same row is reopened (flaps += 1)

Alerts whose scope could not be checked (node unreachable, CF API failing) are left
as they are instead of being resolved. Changes are passed to Telegram / Discord.
Every DRIFT_EVERY seconds it also checks managed config files for changes made outside the
dashboard (history.check_drift), and it announces newly available dashboard versions.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time

import httpx

from . import notify
from .collect import build_alerts, collect_all, kpis
from .state import st

log = logging.getLogger("gwconsole.alerts")
RESOLVE_AFTER = 2
FLAP_WINDOW = 600
FLAP_QUIET = 3          # after this many flaps, stop notifying on re-fire
DRIFT_EVERY = int(os.environ.get("GWC_DRIFT_EVERY", "900"))


def is_muted(alert: dict, mutes: list[dict]) -> dict | None:
    for m in mutes:
        if m["match"] == alert["key"] or (m["match"].startswith("node:") and alert.get("node") == m["match"][5:]):
            return m
    return None


class Engine:
    def __init__(self):
        self.task: asyncio.Task | None = None
        self.last_run = 0
        self.last_error = ""
        self.last_snapshot: dict | None = None
        self._lock = asyncio.Lock()
        self._last_purge = 0
        self._last_drift = 0
        self.drift: list[dict] = []
        self.http = httpx.AsyncClient(timeout=15)

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self.task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self):
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
        await self.http.aclose()

    async def _loop(self):
        await asyncio.sleep(3)
        while True:
            try:
                await self.check_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # never let the loop die
                self.last_error = f"{type(e).__name__}: {e}"
                log.exception("alert check failed")
            await asyncio.sleep(max(10, int(st.s.alert_interval)))

    # ------------------------------------------------------------ one round
    async def check_once(self) -> dict:
        async with self._lock:
            hp, tun = await collect_all()
            current, unknown = build_alerts(hp, tun, bool(st.s.cf_accounts))
            current += await self.drift_alerts()
            changes = self.process(current, unknown, int(time.time()))
            self.last_run = int(time.time())
            self.last_error = ""
            self.last_snapshot = {"at": self.last_run, "kpi": kpis(hp, tun)}
            await self.dispatch(changes)
            await self.update_notice()
            self.purge()
            return {"changes": len(changes), "active": len(current)}

    def process(self, current: list[dict], unknown: dict, t: int) -> list[dict]:
        db = st.store.db
        mutes = self.mutes(t)
        changes: list[dict] = []
        with db.tx():
            open_rows = {r["key"]: r for r in db.q("SELECT * FROM alerts WHERE resolved_at IS NULL")}
            seen = set()
            for a in current:
                seen.add(a["key"])
                row = open_rows.get(a["key"])
                if row:
                    escalated = row["severity"] == "warn" and a["sev"] == "crit"
                    db.x("UPDATE alerts SET last_seen=?, message=?, severity=?, misses=0, node=?, target=? WHERE id=?",
                         (t, a["msg"], a["sev"], a["node"], a["where"], row["id"]))
                    if escalated:
                        changes.append(self._change("escalated", a, row["first_seen"], t, mutes))
                    continue
                recent = db.one("SELECT * FROM alerts WHERE key=? AND resolved_at >= ? ORDER BY resolved_at DESC LIMIT 1",
                                (a["key"], t - FLAP_WINDOW))
                if recent:
                    db.x("UPDATE alerts SET resolved_at=NULL, last_seen=?, message=?, severity=?, misses=0, "
                         "flaps=flaps+1, acked_by=NULL, acked_at=NULL WHERE id=?",
                         (t, a["msg"], a["sev"], recent["id"]))
                    if recent["flaps"] + 1 < FLAP_QUIET:
                        changes.append(self._change("reopened", a, recent["first_seen"], t, mutes))
                else:
                    db.x("INSERT INTO alerts (key, kind, severity, node, target, message, first_seen, last_seen) "
                         "VALUES (?,?,?,?,?,?,?,?)", (a["key"], a["kind"], a["sev"], a["node"], a["where"], a["msg"], t, t))
                    changes.append(self._change("opened", a, t, t, mutes))
            for key, row in open_rows.items():
                if key in seen:
                    continue
                if self._scope_unknown(row, unknown):
                    continue
                misses = row["misses"] + 1
                if misses >= RESOLVE_AFTER:
                    db.x("UPDATE alerts SET resolved_at=?, misses=? WHERE id=?", (t, misses, row["id"]))
                    a = {"key": key, "sev": row["severity"], "node": row["node"], "where": row["target"],
                         "msg": row["message"]}
                    changes.append(self._change("resolved", a, row["first_seen"], t, mutes))
                else:
                    db.x("UPDATE alerts SET misses=? WHERE id=?", (misses, row["id"]))
        return changes

    @staticmethod
    def _scope_unknown(row: dict, unknown: dict) -> bool:
        if row["kind"] == "node.unreachable":
            return False
        if row["node"] and row["node"] in unknown["nodes"]:
            return True
        return unknown["cf"] and (row["kind"].startswith(("tun.edge", "dns.")) or row["kind"] == "tun.not_found")

    @staticmethod
    def _change(event, a, first_seen, t, mutes) -> dict:
        return {"event": event, "key": a["key"], "sev": a["sev"], "node": a.get("node"), "where": a["where"],
                "msg": a["msg"], "duration": t - first_seen, "muted": bool(is_muted(a, mutes))}

    # ------------------------------------------------------------ mutes / retention
    def mutes(self, t: int | None = None) -> list[dict]:
        return st.store.db.q("SELECT * FROM mutes WHERE until > ? ORDER BY until", (t or int(time.time()),))

    def purge(self):
        t = int(time.time())
        if t - self._last_purge < 3600:
            return
        self._last_purge = t
        days = max(1, int(st.s.alert_retention_days))
        st.store.db.x("DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?", (t - days * 86400,))
        st.store.db.x("DELETE FROM mutes WHERE until < ?", (t - 86400,))

    # ------------------------------------------------------------ notifications
    async def dispatch(self, changes: list[dict]):
        changes = [c for c in changes if not c["muted"]]
        if not changes:
            return
        cfg = st.store.notify_cfg()
        status = st.store.get("notify_status", {}) or {}
        for ch in ("telegram", "discord"):
            c = cfg[ch]
            if not c.get("enabled"):
                continue
            mine = [x for x in changes if notify.wanted(x, c)]
            if not mine:
                continue
            try:
                await self.send(ch, c, notify.render(mine, st.s.dashboard_url, html=(ch == "telegram")))
                status[ch] = {"at": int(time.time()), "ok": True, "error": "", "sent": len(mine)}
            except Exception as e:
                status[ch] = {"at": int(time.time()), "ok": False, "error": str(e)[:300], "sent": 0}
                log.warning("notification via %s failed: %s", ch, e)
        st.store.put("notify_status", status)

    async def drift_alerts(self) -> list[dict]:
        """Config files changed outside the dashboard: re-checked every DRIFT_EVERY s, kept between."""
        from . import history
        if not st.store.general().get("drift_check", True):
            self.drift = []
            return []
        if time.time() - self._last_drift >= DRIFT_EVERY:
            self._last_drift = time.time()
            try:
                self.drift = await history.check_drift(st)
            except Exception as e:
                log.warning("drift check failed: %s", e)
        # accepted or overwritten since the last check → drop right away
        self.drift = [a for a in self.drift if st.store.get(f"cfg_drift:{a['where']}")]
        return list(self.drift)

    async def update_notice(self):
        """Tell the notification channels once about each new dashboard version."""
        from .api_system import helper_status
        s = helper_status()
        latest, cur = s.get("latest"), s.get("current")
        if not latest or latest == cur or st.store.get("update_notified") == latest:
            return
        st.store.put("update_notified", latest)
        url = st.s.dashboard_url
        await self.announce(f"Gateway Console {latest} is available (you have {cur}). "
                            f"Open Settings → About to see what's new and update{(' — ' + url + '/#/settings/about') if url else ''}.")

    async def announce(self, text: str):
        """Send a one-off message to every enabled channel (no severity filter)."""
        cfg = st.store.notify_cfg()
        for ch in ("telegram", "discord"):
            c = cfg[ch]
            if not c.get("enabled"):
                continue
            try:
                body = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if ch == "telegram" else text
                await self.send(ch, c, ("ℹ️ " if ch == "telegram" else "ℹ️ ") + body)
            except Exception as e:
                log.warning("announcement via %s failed: %s", ch, e)

    async def send(self, ch: str, c: dict, text: str):
        v = st.store.vault
        if ch == "telegram":
            await notify.send_telegram(self.http, v.decrypt(c["bot_token_enc"]), c["chat_id"], text)
        else:
            await notify.send_discord(self.http, v.decrypt(c["webhook_enc"]), text)
