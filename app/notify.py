"""Telegram and Discord notifications for alert changes.

Only new alerts, escalations and recoveries are sent (never repeats while an alert keeps
firing), batched into one message per channel per check round.
"""
from __future__ import annotations

import os
import re

import httpx

TELEGRAM_API = os.environ.get("GWC_TELEGRAM_API", "https://api.telegram.org")
BOT_TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,64}$")
CHAT_ID_RE = re.compile(r"^(-?\d{3,20}|@[A-Za-z0-9_]{5,64})$")
WEBHOOK_RE = re.compile(r"^https://(discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)"
                        r"/api/webhooks/\d+/[A-Za-z0-9_-]+$")
SEV_LEVEL = {"warn": 1, "crit": 2}
ICON = {"opened": "🔴", "reopened": "🔁", "escalated": "⏫", "resolved": "✅"}
LABEL = {"opened": "FIRING", "reopened": "FIRING AGAIN", "escalated": "ESCALATED", "resolved": "RESOLVED"}


class NotifyError(Exception):
    pass


def validate_telegram(bot_token: str, chat_id: str):
    if not BOT_TOKEN_RE.match(bot_token or ""):
        raise ValueError("bot token looks wrong (expected 123456789:AA... from @BotFather)")
    if not CHAT_ID_RE.match(chat_id or ""):
        raise ValueError("chat ID must be a number (e.g. 123456789 or -1001234567890) or @channelname")


def validate_webhook(url: str):
    if os.environ.get("GWC_ALLOW_ANY_WEBHOOK") == "1" and re.match(r"^https?://", url or ""):
        return
    if not WEBHOOK_RE.match(url or ""):
        raise ValueError("Discord webhook must look like https://discord.com/api/webhooks/<id>/<token>")


def _dur(sec: int) -> str:
    sec = max(0, int(sec))
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m" if m else f"{sec}s"


def wanted(change: dict, ch_cfg: dict) -> bool:
    if change["event"] == "resolved" and not ch_cfg.get("recoveries", True):
        return False
    return SEV_LEVEL.get(change["sev"], 1) >= SEV_LEVEL.get(ch_cfg.get("min_severity", "warn"), 1)


def render(changes: list[dict], dashboard_url: str, html: bool) -> str:
    esc = (lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")) if html else (lambda s: s)
    b = (lambda s: f"<b>{esc(s)}</b>") if html else (lambda s: f"**{s}**")
    firing = sum(1 for c in changes if c["event"] != "resolved")
    head = f"GW//CONSOLE — {firing} firing, {len(changes) - firing} resolved" if len(changes) > 1 else "GW//CONSOLE"
    lines = [b(head)]
    for c in changes[:25]:
        sev = "CRIT" if c["sev"] == "crit" else "WARN"
        tail = f" (after {_dur(c['duration'])})" if c["event"] == "resolved" else ""
        lines.append(f"{ICON[c['event']]} {b(LABEL[c['event']] + ' ' + sev)} {esc(c['where'])}{esc(tail)}\n    {esc(c['msg'])}")
    if len(changes) > 25:
        lines.append(f"… and {len(changes) - 25} more")
    if dashboard_url:
        lines.append(f"{dashboard_url}/#/alerts")
    return "\n".join(lines)


async def send_telegram(client: httpx.AsyncClient, bot_token: str, chat_id: str, text: str):
    r = await client.post(f"{TELEGRAM_API}/bot{bot_token}/sendMessage",
                          json={"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML",
                                "disable_web_page_preview": True}, timeout=15)
    try:
        j = r.json()
    except ValueError:
        j = {}
    if r.status_code != 200 or not j.get("ok", False):
        raise NotifyError(f"Telegram: {j.get('description') or f'HTTP {r.status_code}'}")


async def send_discord(client: httpx.AsyncClient, webhook: str, text: str):
    chunks = [text[i:i + 1900] for i in range(0, len(text), 1900)] or [""]
    for chunk in chunks:
        r = await client.post(webhook, json={"content": chunk, "allowed_mentions": {"parse": []}}, timeout=15)
        if r.status_code not in (200, 204):
            msg = ""
            try:
                msg = r.json().get("message", "")
            except ValueError:
                pass
            raise NotifyError(f"Discord: {msg or f'HTTP {r.status_code}'}")
