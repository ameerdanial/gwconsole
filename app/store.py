"""Data access for users (with preferences), sessions (with idle sign-out), settings, Cloudflare accounts and nodes,
plus the one-time import from config.yaml and building the runtime Settings."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
import secrets
import time

from .auth import hash_password, verify_password
from .config import (
    NAME_RE,
    CFAccount,
    CloudflaredNode,
    HAProxyNode,
    ServerNode,
    Settings,
    Tunnel,
)
from .db import DB
from .vault import Vault

NODE_CLASSES = {"haproxy": HAProxyNode, "cloudflared": CloudflaredNode, "server": ServerNode}
ROLES = ("viewer", "operator", "superadmin")
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}
USER_RE = re.compile(r"^[A-Za-z0-9_.@-]{2,48}$")
MIN_PW = 10

GENERAL_DEFAULTS = {
    "session_hours": 12,
    "alert_interval": 30,
    "alert_retention_days": 90,
    "dashboard_url": "",
    "keep_backups": 20,
    # v1.3
    "update_check": True,          # daily check for new versions (root helper)
    "auto_update_patch": False,    # install x.y.Z patch releases automatically
    "nightly_backup": True,
    "backup_copy_node": "",        # copy nightly backups to this node over SSH ("" = off)
    "backup_copy_dir": "/var/backups/gwconsole-dashboard",
    "signin_alerts": True,         # message on sign-in from a new IP and on failed-login bursts
    "allowed_networks": "",        # sign-in only from these CIDRs ("" = anywhere)
    "drift_check": True,           # alert when a config file is changed outside the dashboard
    # v1.4
    "update_notify": True,         # message Telegram/Discord when a new dashboard version is out
    # v1.4.1
    "max_idle_minutes": 0,         # longest "sign me out when I'm away" anyone may choose (0 = no limit)
    # v1.5
    "twofa_required": "superadmin",  # nobody | superadmin | everyone (installs upgraded from 1.4 start at "nobody")
}
TWOFA_POLICIES = ("nobody", "superadmin", "everyone")
IDLE_CHOICES = (0, 15, 30, 60, 240, 480)      # minutes; 0 = only when the sign-in itself ends
PREF_DEFAULTS = {
    "time24": True,                # 14:05 vs 2:05 PM
    "date_style": "text",          # text = 4 Nov 2026 · dmy = 04/11/2026 · iso = 2026-11-04
    "tz": "",                      # IANA time zone; "" = the browser's
    "start_page": "overview",
    "auto_refresh": True,
    "idle_minutes": 0,             # sign me out when I'm away for … (0 = only when the sign-in ends)
}
START_PAGES = ("overview", "monitoring", "traffic", "tunnels", "haproxy", "alerts", "activity")
BOOL_SETTINGS = {"update_check", "auto_update_patch", "nightly_backup", "signin_alerts", "drift_check", "update_notify"}
MONITOR_DEFAULTS = {               # v1.4: Settings → Monitoring
    "check_every": 60,              # seconds between site checks
    "health_every": 60,             # seconds between server health reads
    "down_after": 3,                # failed checks in a row before a site is "down"
    "slow_ms": 1500,                # slower than this = "slow" (per-site override)
    "disk_warn": 80, "disk_crit": 90,
    "mem_crit": 95,
    "load_factor": 2.0, "load_minutes": 10,     # load above factor × cores for N minutes
    "err5xx_pct": 5, "err5xx_min": 50, "err5xx_minutes": 5,
    "cert_warn": 14, "cert_crit": 3,
    "keep_raw_hours": 48, "keep_15m_days": 30, "keep_daily_days": 365,
    "summary_enabled": True, "summary_day": 0, "summary_time": "09:00",
    "summary_tz": "Asia/Kuala_Lumpur", "summary_telegram": True, "summary_discord": True,
}
MONITOR_LIMITS = {
    "check_every": (30, 3600), "health_every": (30, 3600), "down_after": (1, 20), "slow_ms": (100, 60000),
    "disk_warn": (10, 100), "disk_crit": (10, 100), "mem_crit": (10, 100), "load_factor": (0.5, 20),
    "load_minutes": (1, 120), "err5xx_pct": (0.1, 100), "err5xx_min": (1, 100000), "err5xx_minutes": (1, 120),
    "cert_warn": (1, 365), "cert_crit": (0, 365), "keep_raw_hours": (6, 336), "keep_15m_days": (1, 365),
    "keep_daily_days": (30, 3650), "summary_day": (0, 6),
}
NOTIFY_DEFAULTS = {
    "telegram": {"enabled": False, "bot_token_enc": "", "chat_id": "", "min_severity": "warn", "recoveries": True},
    "discord": {"enabled": False, "webhook_enc": "", "min_severity": "warn", "recoveries": True},
}


def now() -> int:
    return int(time.time())


def _tok_hash(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def normalize_networks(v) -> str:
    """'192.168.10.0/24, 100.64.0.0/10' → canonical, validated, comma-separated."""
    import ipaddress
    out = []
    for part in re.split(r"[\s,]+", str(v or "").strip()):
        if not part:
            continue
        try:
            out.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            raise ValueError(f"'{part}' is not an IP address or network (e.g. 192.168.10.0/24)")
    return ", ".join(dict.fromkeys(out))


def ip_allowed(ip: str, networks: str) -> bool:
    import ipaddress
    if not networks.strip():
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_loopback or any(a in ipaddress.ip_network(n.strip(), strict=False) for n in networks.split(",") if n.strip())


def check_password_strength(pw: str):
    if len(pw) < MIN_PW:
        raise ValueError(f"password must be at least {MIN_PW} characters")
    if pw.lower() == pw or pw.upper() == pw or not any(c.isdigit() for c in pw):
        raise ValueError("password needs upper and lower case letters and a digit")


class Store:
    def __init__(self, db: DB, vault: Vault):
        self.db, self.vault = db, vault

    # ---------------------------------------------------------------- users
    def users(self) -> list[dict]:
        rows = self.db.q("SELECT id, username, role, disabled, must_change, created_at, last_login, pw_changed_at, "
                         "scope_mode, totp_on FROM users ORDER BY username")
        items = {}
        for r in self.db.q("SELECT user_id, kind, ref FROM user_scope ORDER BY kind, ref"):
            items.setdefault(r["user_id"], []).append({"kind": r["kind"], "ref": r["ref"]})
        for r in rows:
            r["totp_on"] = bool(r["totp_on"])
            r["scope"] = items.get(r["id"], []) if r["scope_mode"] == "pick" else []
        return rows

    # ---------------------------------------------------------------- scoped access (v1.5)
    def scope_items(self, uid: int) -> list[dict]:
        return self.db.q("SELECT kind, ref FROM user_scope WHERE user_id=? ORDER BY kind, ref", (uid,))

    def set_scope(self, uid: int, mode: str, items: list[dict]) -> dict:
        """mode 'all' (everything their role allows) or 'pick' (only the tunnels, domains and extra backends given)."""
        u = self.user_by_id(uid)
        if not u:
            raise KeyError("no such user")
        if mode not in ("all", "pick"):
            raise ValueError("access must be 'all' or 'pick'")
        clean = []
        if mode == "pick":
            if u["role"] == "superadmin":
                raise ValueError("a superadmin always has everything — change the role first")
            for i in items or []:
                kind, ref = str(i.get("kind", "")), str(i.get("ref", "")).strip()
                if kind == "domain":
                    ref = ref.lower().rstrip(".")
                    if not re.fullmatch(r"(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", ref):
                        raise ValueError(f"{ref or 'empty'} isn't a domain name (use example.com or *.example.com)")
                elif kind in ("tunnel", "backend"):
                    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}/[A-Za-z0-9_.:\-]{1,128}", ref):
                        raise ValueError(f"{ref or 'empty'} must look like node/name")
                else:
                    raise ValueError(f"unknown kind {kind}")
                if (kind, ref) not in {(c["kind"], c["ref"]) for c in clean}:
                    clean.append({"kind": kind, "ref": ref})
            if not clean:
                raise ValueError("pick at least one tunnel, domain or backend (or choose Everything)")
            if len(clean) > 200:
                raise ValueError("too many items")
        before = {"mode": u["scope_mode"], "items": self.scope_items(uid)}
        with self.db.tx():
            self.db.x("DELETE FROM user_scope WHERE user_id=?", (uid,))
            for c in clean:
                self.db.x("INSERT INTO user_scope (user_id, kind, ref) VALUES (?,?,?)", (uid, c["kind"], c["ref"]))
            self.db.x("UPDATE users SET scope_mode=?, scope_ver=scope_ver+1 WHERE id=?", (mode, uid))
        return {"before": before, "after": {"mode": mode, "items": clean}}

    def scoped_users(self) -> list[str]:
        return [r["username"] for r in self.db.q("SELECT username FROM users WHERE scope_mode='pick' AND disabled=0")]

    def user(self, username: str) -> dict | None:
        return self.db.one("SELECT * FROM users WHERE username = ?", (username,))

    def user_by_id(self, uid: int) -> dict | None:
        return self.db.one("SELECT * FROM users WHERE id = ?", (uid,))

    def active_superadmins(self) -> int:
        return self.db.one("SELECT COUNT(*) n FROM users WHERE role='superadmin' AND disabled=0")["n"]

    def create_user(self, username: str, password: str, role: str, must_change: bool = True,
                    pw_hash: str | None = None, check_strength: bool = True) -> int:
        if not USER_RE.match(username or ""):
            raise ValueError("username: 2-48 chars, letters, digits, _ . @ -")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        if self.user(username):
            raise ValueError(f"user {username} already exists")
        if pw_hash is None:
            if check_strength:
                check_password_strength(password)
            pw_hash = hash_password(password)
        return self.db.x("INSERT INTO users (username, pw_hash, role, must_change, created_at, pw_changed_at) "
                         "VALUES (?,?,?,?,?,?)", (username, pw_hash, role, int(must_change), now(), now()))

    def verify(self, username: str, password: str) -> dict | None:
        u = self.user(username)
        if u and not u["disabled"] and verify_password(password, u["pw_hash"]):
            return u
        return None

    def set_password(self, uid: int, password: str, must_change: bool = False, check_strength: bool = True):
        if check_strength:
            check_password_strength(password)
        self.db.x("UPDATE users SET pw_hash=?, must_change=?, pw_changed_at=? WHERE id=?",
                  (hash_password(password), int(must_change), now(), uid))
        self.db.x("DELETE FROM trusted_browsers WHERE user_id=?", (uid,))   # a new password asks for the code again

    # ---------------------------------------------------------------- two-step sign-in (v1.5)
    def twofa_status(self, uid: int) -> dict:
        u = self.user_by_id(uid) or {}
        rc = json.loads(u.get("totp_recovery") or "[]")
        n = self.db.one("SELECT COUNT(*) n FROM trusted_browsers WHERE user_id=? AND expires_at > ?", (uid, now()))["n"]
        return {"on": bool(u.get("totp_on")), "set_at": u.get("totp_set_at"),
                "recovery_left": sum(1 for r in rc if not r.get("used")) if u.get("totp_on") else 0,
                "required": self.twofa_required_for(u.get("role", "")), "trusted_browsers": n}

    def twofa_start(self, uid: int) -> str:
        """A new secret, kept as pending until the user proves their app shows the right code."""
        from . import totp
        secret = totp.new_secret()
        self.db.x("UPDATE users SET totp_pending=? WHERE id=?", (self.vault.encrypt(secret), uid))
        return secret

    def twofa_confirm(self, uid: int, code: str) -> list[str]:
        from . import totp
        u = self.user_by_id(uid)
        secret = self.vault.decrypt((u or {}).get("totp_pending") or "")
        if not secret:
            raise ValueError("start the setup again")
        step = totp.verify(secret, code)
        if step is None:
            raise ValueError("that code doesn't match — check the phone's clock and try the newest code")
        codes = totp.new_recovery_codes()
        self.db.x("UPDATE users SET totp_secret=?, totp_pending=NULL, totp_on=1, totp_last_step=?, totp_recovery=?, "
                  "totp_set_at=? WHERE id=?", (self.vault.encrypt(secret), step, json.dumps([totp.hash_recovery(c) for c in codes]),
                                               now(), uid))
        return codes

    def twofa_check(self, uid: int, code: str = "", recovery: str = "") -> str | None:
        """'code' or 'recovery' when it matches (and marks it used), None otherwise."""
        from . import totp
        u = self.user_by_id(uid)
        if not u or not u["totp_on"]:
            return None
        if code:
            step = totp.verify(self.vault.decrypt(u["totp_secret"] or ""), code, int(u["totp_last_step"] or 0))
            if step is not None:
                self.db.x("UPDATE users SET totp_last_step=? WHERE id=?", (step, uid))
                return "code"
        if recovery:
            rc = json.loads(u["totp_recovery"] or "[]")
            i = totp.match_recovery(recovery, rc)
            if i is not None:
                rc[i]["used"] = now()
                self.db.x("UPDATE users SET totp_recovery=? WHERE id=?", (json.dumps(rc), uid))
                return "recovery"
        return None

    def twofa_new_recovery(self, uid: int) -> list[str]:
        from . import totp
        codes = totp.new_recovery_codes()
        self.db.x("UPDATE users SET totp_recovery=? WHERE id=?", (json.dumps([totp.hash_recovery(c) for c in codes]), uid))
        return codes

    def twofa_off(self, uid: int):
        """Turn two-step sign-in off (also a superadmin's reset): secret, codes and remembered browsers go."""
        self.db.x("UPDATE users SET totp_on=0, totp_secret=NULL, totp_pending=NULL, totp_last_step=0, totp_recovery='[]', "
                  "totp_set_at=NULL WHERE id=?", (uid,))
        self.db.x("DELETE FROM trusted_browsers WHERE user_id=?", (uid,))

    def trust_browser(self, uid: int, days: int = 30, ip: str = "", ua: str = "") -> str:
        tok = secrets.token_urlsafe(32)
        t = now()
        self.db.x("INSERT INTO trusted_browsers (token_hash, user_id, created_at, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?)",
                  (_tok_hash(tok), uid, t, t + days * 86400, ip, (ua or "")[:200]))
        return tok

    def trusted(self, uid: int, tok: str | None) -> bool:
        if not tok:
            return False
        self.db.x("DELETE FROM trusted_browsers WHERE expires_at < ?", (now(),))
        return bool(self.db.one("SELECT 1 FROM trusted_browsers WHERE token_hash=? AND user_id=?", (_tok_hash(tok), uid)))

    def forget_browsers(self, uid: int) -> int:
        return self.db.x("DELETE FROM trusted_browsers WHERE user_id=?", (uid,))

    def _guard_last_superadmin(self, uid: int, new_role: str | None = None, disabling: bool = False):
        u = self.user_by_id(uid)
        if not u:
            raise KeyError("user not found")
        if u["role"] == "superadmin" and not u["disabled"] and (disabling or (new_role and new_role != "superadmin")):
            if self.active_superadmins() <= 1:
                raise ValueError("this is the last active superadmin; promote someone else first")
        return u

    def set_role(self, uid: int, role: str):
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        self._guard_last_superadmin(uid, new_role=role)
        self.db.x("UPDATE users SET role=? WHERE id=?", (role, uid))
        if role == "superadmin":                  # a superadmin always has everything
            self.db.x("UPDATE users SET scope_mode='all', scope_ver=scope_ver+1 WHERE id=?", (uid,))
            self.db.x("DELETE FROM user_scope WHERE user_id=?", (uid,))

    def set_disabled(self, uid: int, disabled: bool):
        self._guard_last_superadmin(uid, disabling=disabled)
        self.db.x("UPDATE users SET disabled=? WHERE id=?", (int(disabled), uid))
        if disabled:
            self.db.x("DELETE FROM sessions WHERE user_id=?", (uid,))

    def delete_user(self, uid: int):
        self._guard_last_superadmin(uid, disabling=True)
        self.db.x("DELETE FROM users WHERE id=?", (uid,))

    def touch_login(self, uid: int):
        self.db.x("UPDATE users SET last_login=? WHERE id=?", (now(), uid))

    # ---------------------------------------------------------------- sessions
    def create_session(self, uid: int, hours: int, ip: str = "", ua: str = "") -> str:
        tok = secrets.token_urlsafe(32)
        t = now()
        self.db.x("INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen, last_active, ip, "
                  "user_agent) VALUES (?,?,?,?,?,?,?,?)",
                  (_tok_hash(tok), uid, t, t + hours * 3600, t, t, ip, (ua or "")[:200]))
        return tok

    # ---------------------------------------------------------------- preferences
    def prefs(self, uid: int) -> dict:
        r = self.db.one("SELECT prefs FROM users WHERE id=?", (uid,))
        p = dict(PREF_DEFAULTS)
        try:
            p.update({k: v for k, v in json.loads((r or {}).get("prefs") or "{}").items() if k in PREF_DEFAULTS})
        except ValueError:
            pass
        return p

    def set_prefs(self, uid: int, patch: dict) -> dict:
        p = self.prefs(uid)
        for k, v in patch.items():
            if k not in PREF_DEFAULTS:
                raise ValueError(f"unknown preference {k}")
            if k in ("time24", "auto_refresh"):
                v = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
            elif k == "date_style":
                if v not in ("text", "dmy", "iso"):
                    raise ValueError("date style must be text, dmy or iso")
            elif k == "start_page":
                if v not in START_PAGES:
                    raise ValueError("unknown start page")
            elif k == "idle_minutes":
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    raise ValueError("idle time must be a number of minutes")
                if v not in IDLE_CHOICES:
                    raise ValueError("idle time must be one of " + ", ".join(map(str, IDLE_CHOICES)) + " minutes")
                cap = int(self.general().get("max_idle_minutes") or 0)
                if cap and (v == 0 or v > cap):
                    raise ValueError(f"your superadmin allows at most {cap} minutes away")
            elif k == "tz":
                v = str(v or "").strip()
                if v and not re.fullmatch(r"[A-Za-z_]+(/[A-Za-z0-9_+\-]+){0,2}|UTC", v):
                    raise ValueError("unknown time zone")
            p[k] = v
        self.db.x("UPDATE users SET prefs=? WHERE id=?", (json.dumps(p), uid))
        return p

    def idle_limit(self, uid: int, prefs: dict | None = None) -> int:
        """Minutes of inactivity after which this user is signed out (0 = only when the sign-in ends).
        The superadmin's cap always applies, also to users who never chose a value."""
        mine = int((prefs or self.prefs(uid)).get("idle_minutes") or 0)
        cap = int(self.general().get("max_idle_minutes") or 0)
        if cap:
            return min(mine, cap) if mine else cap
        return mine

    def session(self, tok: str | None, idle: int | None = None) -> dict | None:
        """Return the user dict for a valid session, refreshing last_seen at most once a minute.
        `idle` = seconds since the person last clicked or typed in the browser (X-GWC-Idle header);
        auto-refresh requests carry it too, so they don't count as being there. When the user's idle
        limit has passed the session is ended and self.expired_reason says why."""
        self.expired_reason = self.expired_user = ""
        if not tok:
            return None
        h = _tok_hash(tok)
        r = self.db.one("SELECT s.token_hash, s.created_at, s.expires_at, s.last_seen, s.last_active, u.id, u.username, "
                        "u.role, u.disabled, u.must_change, u.prefs, u.scope_mode, u.scope_ver, u.totp_on "
                        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (h,))
        if not r:
            return None
        t = now()
        if r["expires_at"] < t or r["disabled"]:
            self.db.x("DELETE FROM sessions WHERE token_hash=?", (h,))
            return None
        try:
            prefs = dict(PREF_DEFAULTS, **{k: v for k, v in json.loads(r["prefs"] or "{}").items() if k in PREF_DEFAULTS})
        except ValueError:
            prefs = dict(PREF_DEFAULTS)
        limit = self.idle_limit(r["id"], prefs)
        last_active = r["last_active"] or r["last_seen"] or r["created_at"]
        if limit and t - last_active > limit * 60:
            self.db.x("DELETE FROM sessions WHERE token_hash=?", (h,))
            self.expired_reason = f"signed out after {limit} minutes away"
            self.expired_user = r["username"]
            return None
        active = t if idle is None else max(last_active, t - max(0, int(idle)))
        if t - r["last_seen"] > 60 or active - last_active > 30:
            self.db.x("UPDATE sessions SET last_seen=?, last_active=? WHERE token_hash=?", (t, active, h))
        return {"id": r["id"], "username": r["username"], "role": r["role"], "must_change": bool(r["must_change"]),
                "sid": h[:16], "idle_limit": limit, "prefs": prefs, "scope_mode": r["scope_mode"],
                "scope_ver": r["scope_ver"], "totp_on": bool(r["totp_on"]),
                "must_setup_2fa": not r["totp_on"] and self.twofa_required_for(r["role"])}

    def twofa_required_for(self, role: str) -> bool:
        p = self.general().get("twofa_required", "nobody")
        return p == "everyone" or (p == "superadmin" and role == "superadmin")

    def purge_sessions(self):
        """Drop sign-ins that have ended: past their absolute expiry, or away longer than the user's idle limit
        (those are otherwise only removed when that browser makes its next request)."""
        t = now()
        self.db.x("DELETE FROM sessions WHERE expires_at < ?", (t,))
        for u in self.db.q("SELECT DISTINCT u.id, u.prefs FROM sessions s JOIN users u ON u.id = s.user_id"):
            try:
                prefs = dict(PREF_DEFAULTS, **{k: v for k, v in json.loads(u["prefs"] or "{}").items() if k in PREF_DEFAULTS})
            except ValueError:
                prefs = dict(PREF_DEFAULTS)
            limit = self.idle_limit(u["id"], prefs)
            if limit:
                self.db.x("DELETE FROM sessions WHERE user_id=? AND COALESCE(last_active, last_seen, created_at) < ?",
                          (u["id"], t - limit * 60))

    def user_sessions(self, uid: int) -> list[dict]:
        self.purge_sessions()
        return self.db.q("SELECT substr(token_hash, 1, 16) AS sid, created_at, expires_at, last_seen, last_active, ip, "
                         "user_agent FROM sessions WHERE user_id=? AND expires_at > ? ORDER BY last_seen DESC", (uid, now()))

    def drop_session(self, tok: str | None):
        if tok:
            self.db.x("DELETE FROM sessions WHERE token_hash=?", (_tok_hash(tok),))

    def drop_session_id(self, sid: str) -> int:
        if not re.fullmatch(r"[0-9a-f]{16}", sid or ""):
            raise ValueError("bad session id")
        return self.db.x("DELETE FROM sessions WHERE substr(token_hash,1,16)=?", (sid,))

    def drop_user_sessions(self, uid: int, keep_tok: str | None = None):
        if keep_tok:
            self.db.x("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (uid, _tok_hash(keep_tok)))
        else:
            self.db.x("DELETE FROM sessions WHERE user_id=?", (uid,))

    def sessions(self) -> list[dict]:
        self.purge_sessions()
        return self.db.q("SELECT substr(s.token_hash,1,16) sid, u.username, u.role, s.created_at, s.last_seen, s.last_active, "
                         "s.expires_at, s.ip, s.user_agent FROM sessions s JOIN users u ON u.id=s.user_id "
                         "ORDER BY s.last_seen DESC")

    # ---------------------------------------------------------------- settings
    def get(self, key: str, default=None):
        r = self.db.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(r["value"]) if r else copy.deepcopy(default)

    def put(self, key: str, value):
        self.db.x("INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, json.dumps(value)))

    def general(self) -> dict:
        g = dict(GENERAL_DEFAULTS)
        g.update(self.get("general", {}) or {})
        return g

    def set_general(self, patch: dict) -> dict:
        g = self.general()
        for k, v in patch.items():
            if k not in GENERAL_DEFAULTS:
                raise ValueError(f"unknown setting {k}")
            if k == "dashboard_url":
                v = str(v or "").strip().rstrip("/")
                if v and not re.match(r"^https?://[^\s]+$", v):
                    raise ValueError("dashboard URL must start with http:// or https://")
            elif k in BOOL_SETTINGS:
                v = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
            elif k == "backup_copy_node":
                v = str(v or "").strip()
                if v and not self.db.one("SELECT 1 FROM nodes WHERE name=?", (v,)):
                    raise ValueError(f"no node named {v}")
            elif k == "backup_copy_dir":
                v = str(v or "").strip().rstrip("/") or GENERAL_DEFAULTS["backup_copy_dir"]
                if not re.fullmatch(r"/[A-Za-z0-9_./\-]{1,200}", v) or ".." in v:
                    raise ValueError("backup folder must be an absolute path")
            elif k == "allowed_networks":
                v = normalize_networks(v)
            elif k == "twofa_required":
                v = str(v)
                if v not in TWOFA_POLICIES:
                    raise ValueError("two-step sign-in can be required for nobody, superadmin or everyone")
            else:
                v = int(v)
                if k == "max_idle_minutes" and v not in IDLE_CHOICES:
                    raise ValueError("longest idle time must be one of " + ", ".join(map(str, IDLE_CHOICES)) + " minutes")
                lim = {"session_hours": (1, 720), "alert_interval": (10, 3600), "max_idle_minutes": (0, 480),
                       "alert_retention_days": (1, 3650), "keep_backups": (1, 500)}[k]
                if not lim[0] <= v <= lim[1]:
                    raise ValueError(f"{k} must be between {lim[0]} and {lim[1]}")
            g[k] = v
        self.put("general", g)
        return g

    def monitor_cfg(self) -> dict:
        m = dict(MONITOR_DEFAULTS)
        m.update(self.get("monitor", {}) or {})
        return m

    def set_monitor(self, patch: dict) -> dict:
        m = self.monitor_cfg()
        for k, v in patch.items():
            if k not in MONITOR_DEFAULTS:
                raise ValueError(f"unknown setting {k}")
            d = MONITOR_DEFAULTS[k]
            if isinstance(d, bool):
                v = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
            elif k == "summary_time":
                v = str(v).strip()
                if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
                    raise ValueError("summary time must be HH:MM (24-hour)")
            elif k == "summary_tz":
                v = str(v).strip()
                try:
                    from zoneinfo import ZoneInfo
                    ZoneInfo(v)
                except Exception:
                    raise ValueError(f"unknown time zone {v!r} (e.g. Asia/Kuala_Lumpur)")
            else:
                try:
                    v = float(v) if isinstance(d, float) else int(float(v))
                except (TypeError, ValueError):
                    raise ValueError(f"{k} must be a number")
                lo, hi = MONITOR_LIMITS[k]
                if not lo <= v <= hi:
                    raise ValueError(f"{k} must be between {lo} and {hi}")
            m[k] = v
        if m["disk_crit"] < m["disk_warn"]:
            raise ValueError("disk critical must be at least the warning level")
        if m["cert_crit"] > m["cert_warn"]:
            raise ValueError("certificate critical days must be fewer than warning days")
        self.put("monitor", m)
        return m

    def notify_cfg(self) -> dict:
        n = copy.deepcopy(NOTIFY_DEFAULTS)
        stored = self.get("notify", {}) or {}
        for ch in n:
            n[ch].update(stored.get(ch, {}))
        return n

    # ---------------------------------------------------------------- Cloudflare accounts
    def cf_accounts(self) -> list[dict]:
        return [{"id": r["id"], "name": r["name"], "account_id": r["account_id"], "has_token": bool(r["token_enc"]),
                 "updated_at": r["updated_at"]}
                for r in self.db.q("SELECT * FROM cf_accounts ORDER BY name")]

    def cf_account(self, name: str) -> CFAccount | None:
        r = self.db.one("SELECT * FROM cf_accounts WHERE name=?", (name,))
        return CFAccount(r["name"], r["account_id"], self.vault.decrypt(r["token_enc"])) if r else None

    def save_cf_account(self, name: str, account_id: str, token: str | None, old_name: str | None = None):
        if not NAME_RE.match(name or ""):
            raise ValueError("name: letters, digits, _ . - only")
        account_id = (account_id or "").strip()
        if not re.fullmatch(r"[0-9a-f]{32}", account_id):
            raise ValueError("Account ID is the 32-character hex string from the Cloudflare dashboard")
        t = now()
        if old_name:
            r = self.db.one("SELECT * FROM cf_accounts WHERE name=?", (old_name,))
            if not r:
                raise KeyError(f"account {old_name} not found")
            if name != old_name and self.db.one("SELECT 1 FROM cf_accounts WHERE name=?", (name,)):
                raise ValueError(f"account {name} already exists")
            enc = self.vault.encrypt(token.strip()) if token else r["token_enc"]
            self.db.x("UPDATE cf_accounts SET name=?, account_id=?, token_enc=?, updated_at=? WHERE id=?",
                      (name, account_id, enc, t, r["id"]))
        else:
            if self.db.one("SELECT 1 FROM cf_accounts WHERE name=?", (name,)):
                raise ValueError(f"account {name} already exists")
            if not token:
                raise ValueError("API token is required")
            self.db.x("INSERT INTO cf_accounts (name, account_id, token_enc, created_at, updated_at) VALUES (?,?,?,?,?)",
                      (name, account_id, self.vault.encrypt(token.strip()), t, t))

    def delete_cf_account(self, name: str):
        if not self.db.x("DELETE FROM cf_accounts WHERE name=?", (name,)):
            raise KeyError(f"account {name} not found")

    # ---------------------------------------------------------------- nodes
    @staticmethod
    def _node_obj(kind: str, name: str, data: dict):
        cls = NODE_CLASSES[kind]
        fields = {f.name for f in dataclasses.fields(cls)}
        kw = {k: v for k, v in data.items() if k in fields and k != "name"}
        if kind == "cloudflared":
            tfields = {f.name for f in dataclasses.fields(Tunnel)}
            kw["tunnels"] = [Tunnel(**{k: v for k, v in t.items() if k in tfields}) for t in data.get("tunnels") or []]
        return cls(name=name, **kw)

    def nodes(self, kind: str | None = None) -> list:
        rows = self.db.q("SELECT * FROM nodes" + (" WHERE kind=?" if kind else "") + " ORDER BY name",
                         (kind,) if kind else ())
        return [self._node_obj(r["kind"], r["name"], json.loads(r["data"])) for r in rows]

    def node_rows(self) -> list[dict]:
        out = []
        for r in self.db.q("SELECT * FROM nodes ORDER BY kind, name"):
            d = json.loads(r["data"])
            d.pop("tunnels", None)
            out.append({"name": r["name"], "kind": r["kind"], **d, "updated_at": r["updated_at"]})
        return out

    def save_node(self, kind: str, obj, old_name: str | None = None):
        if kind not in NODE_CLASSES:
            raise ValueError("kind must be haproxy, cloudflared or server")
        if not NAME_RE.match(obj.name or ""):
            raise ValueError("node name: letters, digits, _ . - only")
        data = dataclasses.asdict(obj)
        data.pop("name")
        t = now()
        clash = self.db.one("SELECT name FROM nodes WHERE name=?", (obj.name,))
        if old_name:
            if obj.name != old_name and clash:
                raise ValueError(f"node {obj.name} already exists")
            if not self.db.x("UPDATE nodes SET name=?, kind=?, data=?, updated_at=? WHERE name=?",
                             (obj.name, kind, json.dumps(data), t, old_name)):
                raise KeyError(f"node {old_name} not found")
            if obj.name != old_name:
                self.db.x("UPDATE services SET node=? WHERE node=?", (obj.name, old_name))
                self.db.x("DELETE FROM health WHERE node=?", (old_name,))
        else:
            if clash:
                raise ValueError(f"node {obj.name} already exists")
            self.db.x("INSERT INTO nodes (name, kind, data, created_at, updated_at) VALUES (?,?,?,?,?)",
                      (obj.name, kind, json.dumps(data), t, t))

    def delete_node(self, name: str):
        if not self.db.x("DELETE FROM nodes WHERE name=?", (name,)):
            raise KeyError(f"node {name} not found")
        self.db.x("DELETE FROM services WHERE node=?", (name,))
        self.db.x("DELETE FROM health WHERE node=?", (name,))

    # ---------------------------------------------------------------- import + runtime
    def import_from_yaml(self, y: Settings) -> dict | None:
        """Copy users, nodes and CF accounts from config.yaml into the DB, exactly once."""
        if self.get("imported_from_yaml"):
            return None
        counts = {"users": 0, "nodes": 0, "cf_accounts": 0}
        with self.db.tx():
            if not self.db.one("SELECT 1 FROM users LIMIT 1"):
                for name, h in y.users.items():
                    if USER_RE.match(name) and h.startswith("scrypt$"):
                        self.create_user(name, "", "superadmin", must_change=False, pw_hash=h)
                        counts["users"] += 1
            for n in y.haproxy_nodes:
                if not self.db.one("SELECT 1 FROM nodes WHERE name=?", (n.name,)):
                    self.save_node("haproxy", n)
                    counts["nodes"] += 1
            for n in y.cloudflared_nodes:
                if not self.db.one("SELECT 1 FROM nodes WHERE name=?", (n.name,)):
                    self.save_node("cloudflared", n)
                    counts["nodes"] += 1
            for a in y.cf_accounts.values():
                if not self.db.one("SELECT 1 FROM cf_accounts WHERE name=?", (a.name,)):
                    t = now()
                    self.db.x("INSERT INTO cf_accounts (name, account_id, token_enc, created_at, updated_at) "
                              "VALUES (?,?,?,?,?)", (a.name, a.account_id, self.vault.encrypt(a.api_token), t, t))
                    counts["cf_accounts"] += 1
            g = self.general()
            g.update({"session_hours": y.session_hours, "keep_backups": y.keep_backups})
            self.put("general", g)
            self.put("imported_from_yaml", {"at": now(), **counts})
        return counts

    def runtime(self, base: Settings) -> Settings:
        """Bootstrap settings from config.yaml + everything managed in the UI."""
        s = copy.copy(base)
        s.haproxy_nodes = self.nodes("haproxy")
        s.cloudflared_nodes = self.nodes("cloudflared")
        s.server_nodes = self.nodes("server")
        s.cf_accounts = {}
        for r in self.db.q("SELECT name FROM cf_accounts ORDER BY name"):
            s.cf_accounts[r["name"]] = self.cf_account(r["name"])
        g = self.general()
        s.session_hours, s.keep_backups = g["session_hours"], g["keep_backups"]
        s.alert_interval, s.alert_retention_days, s.dashboard_url = (
            g["alert_interval"], g["alert_retention_days"], g["dashboard_url"])
        s.users = {}
        return s
