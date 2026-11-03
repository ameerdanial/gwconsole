"""Data access for users, sessions, settings, Cloudflare accounts and nodes,
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
from .config import NAME_RE, CFAccount, CloudflaredNode, HAProxyNode, Settings, Tunnel
from .db import DB
from .vault import Vault

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
}
BOOL_SETTINGS = {"update_check", "auto_update_patch", "nightly_backup", "signin_alerts", "drift_check"}
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
        return self.db.q("SELECT id, username, role, disabled, must_change, created_at, last_login, pw_changed_at "
                         "FROM users ORDER BY username")

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
        self.db.x("INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen, ip, user_agent) "
                  "VALUES (?,?,?,?,?,?,?)", (_tok_hash(tok), uid, t, t + hours * 3600, t, ip, (ua or "")[:200]))
        return tok

    def session(self, tok: str | None) -> dict | None:
        """Return the user dict for a valid session (and refresh last_seen at most once a minute)."""
        if not tok:
            return None
        h = _tok_hash(tok)
        r = self.db.one("SELECT s.token_hash, s.expires_at, s.last_seen, u.id, u.username, u.role, u.disabled, "
                        "u.must_change FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (h,))
        if not r:
            return None
        t = now()
        if r["expires_at"] < t or r["disabled"]:
            self.db.x("DELETE FROM sessions WHERE token_hash=?", (h,))
            return None
        if t - r["last_seen"] > 60:
            self.db.x("UPDATE sessions SET last_seen=? WHERE token_hash=?", (t, h))
        return {"id": r["id"], "username": r["username"], "role": r["role"], "must_change": bool(r["must_change"]),
                "sid": h[:16]}

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
        self.db.x("DELETE FROM sessions WHERE expires_at < ?", (now(),))
        return self.db.q("SELECT substr(s.token_hash,1,16) sid, u.username, u.role, s.created_at, s.last_seen, "
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
            else:
                v = int(v)
                lim = {"session_hours": (1, 720), "alert_interval": (10, 3600),
                       "alert_retention_days": (1, 3650), "keep_backups": (1, 500)}[k]
                if not lim[0] <= v <= lim[1]:
                    raise ValueError(f"{k} must be between {lim[0]} and {lim[1]}")
            g[k] = v
        self.put("general", g)
        return g

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
        cls = HAProxyNode if kind == "haproxy" else CloudflaredNode
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
        if kind not in ("haproxy", "cloudflared"):
            raise ValueError("kind must be haproxy or cloudflared")
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
        else:
            if clash:
                raise ValueError(f"node {obj.name} already exists")
            self.db.x("INSERT INTO nodes (name, kind, data, created_at, updated_at) VALUES (?,?,?,?,?)",
                      (obj.name, kind, json.dumps(data), t, t))

    def delete_node(self, name: str):
        if not self.db.x("DELETE FROM nodes WHERE name=?", (name,)):
            raise KeyError(f"node {name} not found")

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
        s.cf_accounts = {}
        for r in self.db.q("SELECT name FROM cf_accounts ORDER BY name"):
            s.cf_accounts[r["name"]] = self.cf_account(r["name"])
        g = self.general()
        s.session_hours, s.keep_backups = g["session_hours"], g["keep_backups"]
        s.alert_interval, s.alert_retention_days, s.dashboard_url = (
            g["alert_interval"], g["alert_retention_days"], g["dashboard_url"])
        s.users = {}
        return s
