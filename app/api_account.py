"""My account APIs, for every signed-in user whatever their role: profile, preferences (time and date
format, time zone, start page, auto-refresh, sign-out when away), two-step sign-in (set up, recovery codes,
remembered browsers, turn off) and their own signed-in browsers."""
from __future__ import annotations

import time

from fastapi import APIRouter, Body, Request

from . import totp
from .auth import verify_password
from .state import COOKIE, audit, st, user
from .store import IDLE_CHOICES, START_PAGES, _tok_hash

router = APIRouter(prefix="/api/account")


@router.get("")
async def account(request: Request):
    u = user(request)
    full = st.store.user_by_id(u["id"]) or {}
    g = st.store.general()
    sess = st.store.user_sessions(u["id"])
    mine = _tok_hash(request.cookies.get(COOKIE) or "")[:16]
    here = next((x for x in sess if x["sid"] == mine), None)
    return {
        "user": u["username"], "role": u["role"], "created_at": full.get("created_at"),
        "last_login": full.get("last_login"), "pw_changed_at": full.get("pw_changed_at"),
        "ip": here["ip"] if here else "",
        "prefs": st.store.prefs(u["id"]), "idle_limit": st.store.idle_limit(u["id"]),
        "twofa": st.store.twofa_status(u["id"]),
        "policy": {"max_idle_minutes": int(g.get("max_idle_minutes") or 0), "session_hours": g["session_hours"]},
        "choices": {"idle_minutes": list(IDLE_CHOICES), "start_page": list(START_PAGES)},
    }


@router.put("/prefs")
async def save_prefs(request: Request, body: dict = Body(...)):
    u = user(request)
    p = st.store.set_prefs(u["id"], body)
    audit(request, "preferences", u["username"], True,
          ", ".join(f"{k}={body[k]}" for k in body if k in p)[:300])
    return {"ok": True, "prefs": p, "idle_limit": st.store.idle_limit(u["id"], p)}


@router.get("/sessions")
async def my_sessions(request: Request):
    u = user(request)
    mine = _tok_hash(request.cookies.get(COOKIE) or "")[:16]
    return {"items": [{**x, "this": x["sid"] == mine} for x in st.store.user_sessions(u["id"])]}


@router.delete("/sessions/{sid}")
async def end_my_session(request: Request, sid: str):
    u = user(request)
    if not any(x["sid"] == sid for x in st.store.user_sessions(u["id"])):
        raise KeyError("no such browser session")
    st.store.drop_session_id(sid)
    audit(request, "session revoke", f"{u['username']} ({sid[:6]})", True, "own browser")
    return {"ok": True}


@router.post("/sessions/others")
async def end_other_sessions(request: Request):
    u = user(request)
    n = len(st.store.user_sessions(u["id"])) - 1
    st.store.drop_user_sessions(u["id"], keep_tok=request.cookies.get(COOKIE))
    n = max(0, n)
    audit(request, "session revoke", u["username"], True, f"signed out {n} other browser{'' if n == 1 else 's'}")
    return {"ok": True, "ended": n}


# ---- two-step sign-in ----------------------------------------------------------------------
@router.post("/2fa/start")
async def twofa_start(request: Request):
    u = user(request)
    if st.store.twofa_status(u["id"])["on"]:
        raise ValueError("two-step sign-in is already on — turn it off first to move it to another phone")
    secret = st.store.twofa_start(u["id"])
    link = totp.uri(secret, u["username"])
    return {"svg": totp.qr_svg(link), "key": totp.pretty(secret), "uri": link, "server_time": int(time.time())}


@router.post("/2fa/confirm")
async def twofa_confirm(request: Request, body: dict = Body(...)):
    u = user(request)
    codes = st.store.twofa_confirm(u["id"], str(body.get("code", "")))
    audit(request, "2fa on", u["username"], True)
    return {"ok": True, "recovery_codes": codes}


def _reauth(request: Request, body: dict):
    """Password, and the current code, before turning it off or making new codes."""
    u = user(request)
    full = st.store.user_by_id(u["id"]) or {}
    if not verify_password(str(body.get("password", "")), full.get("pw_hash", "")):
        raise ValueError("wrong password")
    if not st.store.twofa_check(u["id"], code=str(body.get("code") or ""), recovery=str(body.get("recovery") or "")):
        raise ValueError("that code doesn't match")
    return u


@router.post("/2fa/off")
async def twofa_off(request: Request, body: dict = Body(...)):
    u = user(request)
    if st.store.twofa_required_for(u["role"]):
        raise ValueError("two-step sign-in is required for your role — ask a superadmin to reset it if you lost your phone")
    _reauth(request, body)
    st.store.twofa_off(u["id"])
    audit(request, "2fa off", u["username"], True)
    return {"ok": True}


@router.post("/2fa/recovery")
async def twofa_recovery(request: Request, body: dict = Body(...)):
    u = _reauth(request, body)
    codes = st.store.twofa_new_recovery(u["id"])
    audit(request, "2fa recovery codes", u["username"], True, "new codes made; the old ones stopped working")
    return {"ok": True, "recovery_codes": codes}


@router.post("/2fa/browsers")
async def twofa_forget_browsers(request: Request):
    u = user(request)
    n = st.store.forget_browsers(u["id"])
    audit(request, "2fa browsers forgotten", u["username"], True, f"{n} remembered browser{'' if n == 1 else 's'}")
    return {"ok": True, "forgotten": n}
