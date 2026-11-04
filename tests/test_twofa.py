"""Tests for v1.5 two-step sign-in: the TOTP codes (RFC 6238), replay and clock-drift rules, recovery codes,
the sign-in flow with a ticket, remembered browsers, lock-out after wrong codes, the "required for" policy,
turning it off, a superadmin's reset, and secrets never stored in the clear."""
import base64

from app import totp

H = {"X-GWC": "1"}


def test_totp_rfc6238_and_rules():
    sec = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(sec, 59 // 30) == "287082"                 # RFC 6238 test vector (6 digits)
    assert totp.code_at(sec, 1111111109 // 30) == "081804"
    s = totp.new_secret()
    step = totp.now_step()
    assert totp.verify(s, totp.code_at(s, step)) == step
    assert totp.verify(s, totp.code_at(s, step - 1)) == step - 1     # 30 s of clock drift is fine
    assert totp.verify(s, totp.code_at(s, step - 3)) is None          # older isn't
    assert totp.verify(s, totp.code_at(s, step), last_step=step) is None   # each code works once
    assert totp.verify(s, "12 34 5") is None and totp.verify(s, "") is None
    codes = totp.new_recovery_codes()
    stored = [totp.hash_recovery(c) for c in codes]
    assert len(set(codes)) == 10 and all(len(c) == 12 for c in codes)
    assert totp.match_recovery(codes[4].lower().replace("-", ""), stored) == 4
    stored[4]["used"] = 1
    assert totp.match_recovery(codes[4], stored) is None
    assert "<svg" in totp.qr_svg(totp.uri(s, "ameer"))


def _login(c, user="root", pw="RootPass1234"):
    return c.post("/api/login", json={"user": user, "password": pw})


def _turn_on(c):
    d = c.post("/api/account/2fa/start", headers=H).json()
    key = d["key"].replace(" ", "")
    r = c.post("/api/account/2fa/confirm", json={"code": totp.code_at(key, totp.now_step())}, headers=H).json()
    return key, r["recovery_codes"]


def test_twofa_sign_in_flow(client):
    from app.state import st
    assert _login(client).status_code == 200
    key, codes = _turn_on(client)
    assert len(codes) == 10
    row = st.store.user("root")
    assert row["totp_on"] and key not in (row["totp_secret"] or "") and codes[0] not in row["totp_recovery"]
    assert client.get("/api/account").json()["twofa"]["recovery_left"] == 10
    client.post("/api/logout", headers=H)
    r = _login(client).json()
    assert r["twofa"] and r["ticket"] and "user" in r
    assert client.get("/api/me").status_code == 401                 # no session from the password alone
    bad = client.post("/api/login/2fa", json={"ticket": r["ticket"], "code": "000000"})
    assert bad.status_code == 401 and bad.json()["twofa"]
    nxt = totp.code_at(key, totp.now_step() + 1)                     # the confirm step used the current one
    ok = client.post("/api/login/2fa", json={"ticket": r["ticket"], "code": nxt, "remember": True})
    assert ok.status_code == 200 and client.get("/api/me").json()["user"] == "root"
    assert client.post("/api/login/2fa", json={"ticket": r["ticket"], "code": nxt}).status_code == 401   # ticket gone
    client.post("/api/logout", headers=H)
    assert "twofa" not in _login(client).json()                       # remembered browser
    client.post("/api/account/2fa/browsers", headers=H)
    client.post("/api/logout", headers=H)
    r = _login(client).json()
    assert r["twofa"]
    rc = client.post("/api/login/2fa", json={"ticket": r["ticket"], "recovery": codes[0]})
    assert rc.status_code == 200 and client.get("/api/account").json()["twofa"]["recovery_left"] == 9
    client.post("/api/logout", headers=H)
    r = _login(client).json()
    assert client.post("/api/login/2fa", json={"ticket": r["ticket"], "recovery": codes[0]}).status_code == 401


def test_wrong_codes_lock_out_and_ticket_is_bound(client):
    _login(client)
    _turn_on(client)
    client.post("/api/logout", headers=H)
    r = _login(client).json()
    other = client.post("/api/login/2fa", json={"ticket": r["ticket"], "code": "123456"}, headers={"User-Agent": "other"})
    assert other.status_code == 401 and other.json().get("restart")
    from app import main
    from app.state import st
    main._code_fails.clear()
    st.logins.locked = lambda addr: False                             # only the per-user limit in this test
    for _ in range(5):
        assert client.post("/api/login/2fa", json={"ticket": r["ticket"], "code": "000000"}).status_code == 401
    assert client.post("/api/login/2fa", json={"ticket": r["ticket"], "code": "000000"}).status_code == 429


def test_policy_forces_setup_and_blocks_turning_off(client):
    from app.state import st
    _login(client)
    st.store.set_general({"twofa_required": "superadmin"})
    me = client.get("/api/me").json()
    assert me["must_setup_2fa"]
    r = client.get("/api/overview")
    assert r.status_code == 403 and r.json()["must_setup_2fa"]
    key, _ = _turn_on(client)
    assert client.get("/api/me").json()["must_setup_2fa"] is False
    off = client.post("/api/account/2fa/off", json={"password": "RootPass1234", "code": totp.code_at(key, totp.now_step() + 1)},
                      headers=H)
    assert off.status_code == 400 and "required" in off.json()["error"]
    st.store.set_general({"twofa_required": "nobody"})
    wrong = client.post("/api/account/2fa/off", json={"password": "nope", "code": "000000"}, headers=H)
    assert wrong.status_code == 400
    ok = client.post("/api/account/2fa/off", json={"password": "RootPass1234", "code": totp.code_at(key, totp.now_step() + 1)},
                     headers=H)
    assert ok.status_code == 200 and not st.store.user("root")["totp_on"]


def test_superadmin_reset_and_password_change(client):
    from app.state import st
    _login(client)
    uid = st.store.create_user("ops1", "OpsPass12345", "operator", must_change=False)
    sec = st.store.twofa_start(uid)
    st.store.twofa_confirm(uid, totp.code_at(sec, totp.now_step()))
    tok = st.store.trust_browser(uid)
    st.store.create_session(uid, 12)
    assert st.store.trusted(uid, tok)
    st.store.set_password(uid, "OpsPass123456")                       # a new password forgets remembered browsers
    assert not st.store.trusted(uid, tok)
    assert client.post(f"/api/admin/users/{uid}/2fa/reset", headers=H).status_code == 200
    assert not st.store.user_by_id(uid)["totp_on"] and not st.store.user_sessions(uid)
    me = st.store.user("root")["id"]
    assert client.post(f"/api/admin/users/{me}/2fa/reset", headers=H).status_code == 400
    assert "2fa reset" in [i["action"] for i in client.get("/api/audit").json()["items"]]
