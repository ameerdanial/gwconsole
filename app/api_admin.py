"""Superadmin APIs: users and sessions, Cloudflare accounts, nodes, notifications and
general settings — plus "change my password" for every signed-in user."""
from __future__ import annotations

import dataclasses
import re
import secrets
import string
import time

from fastapi import APIRouter, Body, Request

from . import notify
from .cfapi import Cloudflare
from .config import CFAccount, CloudflaredNode, HAProxyNode
from .inventory import Inventory
from .sshpool import NodeError, SSHPool, scan_host_key
from .state import COOKIE, audit, need, st, user
from .store import ROLES, check_password_strength

router = APIRouter(prefix="/api")
HOST_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
                     r"|^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]{2,39}$")
UNIX_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_./@+-]{1,250}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,100}$")
KEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|rsa-sha2-(256|512)) [A-Za-z0-9+/=]{40,1000}$")


def temp_password() -> str:
    alpha = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alpha) for _ in range(14))
        try:
            check_password_strength(pw)
            return pw
        except ValueError:
            continue


# ---- my account ---------------------------------------------------------------
@router.post("/account/password")
async def change_my_password(request: Request, body: dict = Body(...)):
    u = user(request)
    full = st.store.user_by_id(u["id"])
    if not st.store.verify(full["username"], str(body.get("current", ""))):
        raise ValueError("current password is wrong")
    new = str(body.get("new", ""))
    if new == str(body.get("current", "")):
        raise ValueError("pick a password different from the current one")
    st.store.set_password(u["id"], new, must_change=False)
    st.store.drop_user_sessions(u["id"], keep_tok=request.cookies.get(COOKIE))
    audit(request, "password change", u["username"], True)
    return {"ok": True}


# ---- users ------------------------------------------------------------------------
@router.get("/admin/users")
async def list_users(request: Request):
    need(request, "superadmin")
    return {"items": st.store.users(), "roles": list(ROLES), "me": user(request)["id"]}


@router.post("/admin/users")
async def create_user(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    name, role = str(body.get("username", "")).strip(), str(body.get("role", "viewer"))
    pw = str(body.get("password") or "") or temp_password()
    st.store.create_user(name, pw, role, must_change=True)
    audit(request, "user create", name, True, f"role={role}")
    return {"ok": True, "temp_password": pw}


@router.patch("/admin/users/{uid}")
async def update_user(request: Request, uid: int, body: dict = Body(...)):
    need(request, "superadmin")
    u = st.store.user_by_id(uid)
    if not u:
        raise KeyError("user not found")
    me = user(request)
    if "role" in body:
        if uid == me["id"] and body["role"] != "superadmin":
            raise ValueError("you can't demote yourself; ask another superadmin")
        st.store.set_role(uid, str(body["role"]))
        audit(request, "user role", u["username"], True, f"{u['role']} -> {body['role']}")
    if "disabled" in body:
        if uid == me["id"]:
            raise ValueError("you can't disable yourself")
        st.store.set_disabled(uid, bool(body["disabled"]))
        audit(request, "user disable" if body["disabled"] else "user enable", u["username"], True)
    return {"ok": True}


@router.post("/admin/users/{uid}/reset")
async def reset_user(request: Request, uid: int):
    need(request, "superadmin")
    u = st.store.user_by_id(uid)
    if not u:
        raise KeyError("user not found")
    pw = temp_password()
    st.store.set_password(uid, pw, must_change=True)
    st.store.drop_user_sessions(uid)
    audit(request, "user password reset", u["username"], True)
    return {"ok": True, "temp_password": pw}


@router.delete("/admin/users/{uid}")
async def delete_user(request: Request, uid: int):
    need(request, "superadmin")
    u = st.store.user_by_id(uid)
    if not u:
        raise KeyError("user not found")
    if uid == user(request)["id"]:
        raise ValueError("you can't delete yourself")
    st.store.delete_user(uid)
    audit(request, "user delete", u["username"], True)
    return {"ok": True}


@router.get("/admin/sessions")
async def list_sessions(request: Request):
    need(request, "superadmin")
    return {"items": st.store.sessions(), "mine": user(request)["sid"]}


@router.delete("/admin/sessions/{sid}")
async def kick_session(request: Request, sid: str):
    need(request, "superadmin")
    if not st.store.drop_session_id(sid):
        raise KeyError("session not found")
    audit(request, "session revoke", sid, True)
    return {"ok": True}


# ---- Cloudflare accounts ------------------------------------------------------------
@router.get("/admin/cf-accounts")
async def cf_accounts(request: Request):
    need(request, "superadmin")
    return {"items": st.store.cf_accounts()}


@router.post("/admin/cf-accounts")
async def cf_create(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    st.store.save_cf_account(str(body.get("name", "")).strip(), str(body.get("account_id", "")),
                             str(body.get("token") or ""))
    await st.reload()
    audit(request, "cf account add", str(body.get("name")), True)
    return {"ok": True}


@router.put("/admin/cf-accounts/{name}")
async def cf_update(request: Request, name: str, body: dict = Body(...)):
    need(request, "superadmin")
    st.store.save_cf_account(str(body.get("name", name)).strip(), str(body.get("account_id", "")),
                             str(body.get("token") or "") or None, old_name=name)
    await st.reload()
    audit(request, "cf account edit", name, True, "token replaced" if body.get("token") else "")
    return {"ok": True}


@router.delete("/admin/cf-accounts/{name}")
async def cf_delete(request: Request, name: str):
    need(request, "superadmin")
    st.store.delete_cf_account(name)
    await st.reload()
    audit(request, "cf account delete", name, True)
    return {"ok": True}


@router.post("/admin/cf-accounts/test")
async def cf_test(request: Request, body: dict = Body(...)):
    """Test a saved account (name) or unsaved values (account_id + token) before saving."""
    need(request, "superadmin")
    if body.get("token"):
        acc_id = str(body.get("account_id", "")).strip()
        if not re.fullmatch(r"[0-9a-f]{32}", acc_id):
            raise ValueError("Account ID is the 32-character hex string from the Cloudflare dashboard")
        acc = CFAccount("test", acc_id, str(body["token"]).strip())
    else:
        acc = st.store.cf_account(str(body.get("name", "")))
        if not acc:
            raise KeyError("account not found")
        if body.get("account_id"):
            acc.account_id = str(body["account_id"]).strip()
    cf = Cloudflare(st.s)
    try:
        return {"results": await cf.check_permissions(acc)}
    finally:
        await cf.close()


# ---- nodes ------------------------------------------------------------------------
NODE_FIELDS = {
    "haproxy": ["config_path", "stats_socket", "backup_dir", "service", "haproxy_bin"],
    "cloudflared": ["cloudflared_bin", "tunnel_base_dir", "discover"],
}


def _node_from_body(kind: str, body: dict, existing=None):
    cls = HAProxyNode if kind == "haproxy" else CloudflaredNode
    base = dataclasses.asdict(existing) if existing else {f.name: f.default for f in dataclasses.fields(cls)
                                                          if f.default is not dataclasses.MISSING}
    if existing and kind == "cloudflared":
        base["tunnels"] = existing.tunnels       # keep per-tunnel overrides
    elif kind == "cloudflared":
        base["tunnels"] = []
    d = dict(base)
    d["name"] = str(body.get("name", d.get("name") or "")).strip()
    host = str(body.get("host", d.get("host") or "")).strip()
    if not HOST_RE.match(host):
        raise ValueError("host must be an IP address or hostname")
    d["host"] = host
    d["port"] = int(body.get("port", d.get("port") or 22))
    if not 1 <= d["port"] <= 65535:
        raise ValueError("port must be 1-65535")
    d["user"] = str(body.get("user", d.get("user") or "root")).strip()
    if not UNIX_USER_RE.match(d["user"]):
        raise ValueError("bad SSH user name")
    d["sudo"] = bool(body.get("sudo", d.get("sudo", False)))
    d["site"] = str(body.get("site", d.get("site") or ""))[:20]
    if "host_key" in body:
        hk = str(body.get("host_key") or "").strip()
        if hk and not KEY_RE.match(hk):
            raise ValueError("host key must be one OpenSSH public key line")
        d["host_key"] = hk
    for f in NODE_FIELDS[kind]:
        if f in body:
            v = body[f]
            if f == "discover":
                d[f] = bool(v)
            elif f in ("service",):
                if not UNIT_RE.match(str(v)):
                    raise ValueError(f"bad {f}")
                d[f] = str(v)
            elif f in ("haproxy_bin", "cloudflared_bin"):
                v = str(v).strip()
                if not (PATH_RE.match(v) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", v)):
                    raise ValueError(f"bad {f}")
                d[f] = v
            else:
                v = str(v).strip().rstrip("/") if f in ("tunnel_base_dir", "backup_dir") else str(v).strip()
                if not PATH_RE.match(v):
                    raise ValueError(f"{f} must be an absolute path")
                d[f] = v
    if kind == "cloudflared":
        from .config import Tunnel
        d["tunnels"] = [t if isinstance(t, Tunnel) else Tunnel(**t) for t in d["tunnels"]]
    fields = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in d.items() if k in fields})


def _find_node(name: str):
    for kind, lst in (("haproxy", st.s.haproxy_nodes), ("cloudflared", st.s.cloudflared_nodes)):
        for n in lst:
            if n.name == name:
                return kind, n
    raise KeyError(f"node {name} not found")


@router.get("/admin/nodes")
async def nodes(request: Request):
    need(request, "superadmin")
    try:
        pub = open(st.s.ssh_key_file + ".pub").read().strip()
    except OSError:
        pub = ""
    return {"items": st.store.node_rows(), "pubkey": pub, "imported": st.store.get("imported_from_yaml")}


@router.post("/admin/nodes/scan")
async def scan(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    host = str(body.get("host", "")).strip()
    if not HOST_RE.match(host):
        raise ValueError("host must be an IP address or hostname")
    return await scan_host_key(host, int(body.get("port", 22)))


@router.post("/admin/nodes")
async def node_create(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    kind = str(body.get("kind", ""))
    if kind not in NODE_FIELDS:
        raise ValueError("kind must be haproxy or cloudflared")
    if not str(body.get("host_key") or "").strip():
        raise ValueError("scan and confirm the host key first")
    obj = _node_from_body(kind, body)
    st.store.save_node(kind, obj)
    await st.reload()
    audit(request, "node add", obj.name, True, f"{kind} {obj.user}@{obj.host}:{obj.port}")
    return {"ok": True}


@router.put("/admin/nodes/{name}")
async def node_update(request: Request, name: str, body: dict = Body(...)):
    need(request, "superadmin")
    kind, existing = _find_node(name)
    obj = _node_from_body(kind, body, existing)
    st.store.save_node(kind, obj, old_name=name)
    await st.reload()
    audit(request, "node edit", name, True, f"{kind} {obj.user}@{obj.host}:{obj.port}")
    return {"ok": True}


@router.delete("/admin/nodes/{name}")
async def node_delete(request: Request, name: str):
    need(request, "superadmin")
    st.store.delete_node(name)
    await st.reload()
    audit(request, "node delete", name, True)
    return {"ok": True}


@router.post("/admin/nodes/test")
async def node_test(request: Request, body: dict = Body(...)):
    """Test SSH + node prerequisites for a saved node (name) or unsaved form values."""
    need(request, "superadmin")
    if body.get("name") and not body.get("host"):
        kind, n = _find_node(str(body["name"]))
    else:
        kind = str(body.get("kind", ""))
        if kind not in NODE_FIELDS:
            raise ValueError("kind must be haproxy or cloudflared")
        existing = None
        if body.get("original"):
            _, existing = _find_node(str(body["original"]))
        n = _node_from_body(kind, {**body, "name": body.get("name") or "test"}, existing)
    pool = SSHPool(st.s)
    checks = []
    try:
        r = await pool.run(n, "id -un; uname -n", root=False)
        checks.append({"check": "SSH login", "ok": r.ok, "detail": r.text.replace("\n", " @ ")})
        if n.sudo:
            r = await pool.run(n, "true")
            checks.append({"check": "sudo without password", "ok": r.ok, "detail": r.err.strip() or "ok"})
        if kind == "haproxy":
            r = await pool.run(n, f"{n.haproxy_bin} -v | head -1")
            checks.append({"check": "haproxy", "ok": r.ok, "detail": r.text})
            r = await pool.run(n, "command -v socat")
            checks.append({"check": "socat", "ok": r.ok, "detail": r.out.strip() or "missing — apt install socat"})
            r = await pool.run(n, f"test -S {n.stats_socket} && echo present")
            checks.append({"check": "admin stats socket", "ok": r.ok,
                           "detail": n.stats_socket if r.ok else
                           f"{n.stats_socket} not found — add 'stats socket {n.stats_socket} mode 660 level admin' to global"})
            r = await pool.run(n, f"test -r {n.config_path} && echo ok")
            checks.append({"check": "config readable", "ok": r.ok, "detail": n.config_path})
        else:
            r = await pool.run(n, f"{n.cloudflared_bin} --version | head -1")
            checks.append({"check": "cloudflared", "ok": r.ok, "detail": r.text})
            try:
                ts = await Inventory(st.s, pool).tunnels(n, fresh=True)
                checks.append({"check": "tunnels discovered", "ok": True,
                               "detail": ", ".join(t.name for t in ts) or "none yet"})
            except NodeError as e:
                checks.append({"check": "tunnels discovered", "ok": False, "detail": str(e)})
    except NodeError as e:
        checks.append({"check": "SSH login", "ok": False, "detail": str(e)})
    finally:
        await pool.close()
    return {"checks": checks}


# ---- notifications ---------------------------------------------------------------
def _notify_view():
    n = st.store.notify_cfg()
    tg, dc = n["telegram"], n["discord"]
    return {
        "telegram": {"enabled": tg["enabled"], "chat_id": tg["chat_id"], "min_severity": tg["min_severity"],
                     "recoveries": tg["recoveries"], "has_bot_token": bool(tg["bot_token_enc"])},
        "discord": {"enabled": dc["enabled"], "min_severity": dc["min_severity"], "recoveries": dc["recoveries"],
                    "has_webhook": bool(dc["webhook_enc"])},
        "status": st.store.get("notify_status", {}) or {},
        "dashboard_url": st.s.dashboard_url,
    }


@router.get("/admin/notify")
async def notify_get(request: Request):
    need(request, "superadmin")
    return _notify_view()


def _merge_channel(ch: str, body: dict, cur: dict) -> dict:
    c = dict(cur)
    c["enabled"] = bool(body.get("enabled", c["enabled"]))
    sev = str(body.get("min_severity", c["min_severity"]))
    if sev not in ("warn", "crit"):
        raise ValueError("minimum severity must be warn or crit")
    c["min_severity"], c["recoveries"] = sev, bool(body.get("recoveries", c["recoveries"]))
    v = st.store.vault
    if ch == "telegram":
        c["chat_id"] = str(body.get("chat_id", c["chat_id"])).strip()
        if body.get("bot_token"):
            notify.validate_telegram(str(body["bot_token"]).strip(), c["chat_id"] or "0000")
            c["bot_token_enc"] = v.encrypt(str(body["bot_token"]).strip())
        if c["enabled"]:
            notify.validate_telegram(v.decrypt(c["bot_token_enc"]), c["chat_id"])
    else:
        if body.get("webhook"):
            notify.validate_webhook(str(body["webhook"]).strip())
            c["webhook_enc"] = v.encrypt(str(body["webhook"]).strip())
        if c["enabled"] and not c["webhook_enc"]:
            raise ValueError("add the Discord webhook URL first")
    return c


@router.put("/admin/notify/{ch}")
async def notify_put(request: Request, ch: str, body: dict = Body(...)):
    need(request, "superadmin")
    if ch not in ("telegram", "discord"):
        raise KeyError("unknown channel")
    allc = st.store.notify_cfg()
    allc[ch] = _merge_channel(ch, body, allc[ch])
    st.store.put("notify", allc)
    audit(request, "notify settings", ch, True, f"enabled={allc[ch]['enabled']} min={allc[ch]['min_severity']}")
    return _notify_view()


@router.post("/admin/notify/{ch}/test")
async def notify_test(request: Request, ch: str, body: dict = Body(default={})):
    """Send a test message with the saved settings, or with unsaved values from the form."""
    need(request, "superadmin")
    if ch not in ("telegram", "discord"):
        raise KeyError("unknown channel")
    c = _merge_channel(ch, {**body, "enabled": False}, st.store.notify_cfg()[ch])
    text = notify.render([{"event": "opened", "sev": "warn", "where": "test", "duration": 0,
                           "msg": f"Test message from GW//CONSOLE sent by {user(request)['username']} "
                                  f"at {time.strftime('%Y-%m-%d %H:%M:%S')}"}], st.s.dashboard_url, html=(ch == "telegram"))
    try:
        await st.engine.send(ch, c, text)
    except notify.NotifyError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True}


# ---- general -----------------------------------------------------------------------
@router.get("/admin/general")
async def general_get(request: Request):
    need(request, "superadmin")
    from . import __version__
    return {"settings": st.store.general(), "imported": st.store.get("imported_from_yaml"),
            "version": __version__, "db_path": st.s.db_path,
            "engine": {"last_run": st.engine.last_run, "last_error": st.engine.last_error}}


@router.put("/admin/general")
async def general_put(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    g = st.store.set_general(body)
    await st.reload()
    audit(request, "settings change", "general", True, ", ".join(f"{k}={v}" for k, v in body.items()))
    return {"settings": g}
