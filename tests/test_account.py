"""Tests for v1.4.1: My account (profile, preferences, own browsers), sign-out when away (idle limit,
superadmin cap, auto-refresh not counting as activity), the Activity search API and CSV, the Overview
data, routes for tunnels that point at localhost, and the database upgrade."""
import json
import sqlite3
import time

import pytest

from app import audit as auditmod
from app import hpcfg, sites
from app.db import DB, MIGRATIONS
from app.store import Store
from app.vault import Vault

H = {"X-GWC": "1"}


def login(c, user="root", pw="RootPass1234"):
    assert c.post("/api/login", json={"user": user, "password": pw}).status_code == 200


def test_prefs_validation_and_idle_cap(store):
    uid = store.create_user("ops1", "OpsPass12345", "operator", must_change=False)
    assert store.prefs(uid)["time24"] is True and store.prefs(uid)["idle_minutes"] == 0
    p = store.set_prefs(uid, {"time24": "false", "date_style": "iso", "tz": "Asia/Kuala_Lumpur", "idle_minutes": "30",
                              "start_page": "monitoring", "auto_refresh": False})
    assert (p["time24"], p["date_style"], p["idle_minutes"], p["start_page"]) == (False, "iso", 30, "monitoring")
    for bad in ({"idle_minutes": 7}, {"date_style": "us"}, {"start_page": "settings"}, {"tz": "../etc"}, {"nope": 1}):
        with pytest.raises(ValueError):
            store.set_prefs(uid, bad)
    assert store.idle_limit(uid) == 30
    store.set_general({"max_idle_minutes": 15})          # superadmin cap applies to everyone
    assert store.idle_limit(uid) == 15
    with pytest.raises(ValueError, match="at most 15"):
        store.set_prefs(uid, {"idle_minutes": 60})
    store.set_prefs(uid, {"idle_minutes": 15})
    other = store.create_user("ops2", "OpsPass12345", "operator", must_change=False)
    assert store.idle_limit(other) == 15                  # never chose: the cap still applies
    with pytest.raises(ValueError):
        store.set_general({"max_idle_minutes": 20})


def test_idle_signout_ignores_auto_refresh(store):
    uid = store.create_user("ops1", "OpsPass12345", "operator", must_change=False)
    store.set_prefs(uid, {"idle_minutes": 15})
    tok = store.create_session(uid, 12)
    assert store.session(tok, idle=0)["idle_limit"] == 15
    h = __import__("app.store", fromlist=["_tok_hash"])._tok_hash(tok)
    # 10 minutes ago the person last clicked; a background refresh now reports 600 s idle
    store.db.x("UPDATE sessions SET last_active=?, last_seen=? WHERE token_hash=?", (int(time.time()) - 600,) * 2 + (h,))
    assert store.session(tok, idle=600) is not None
    la = store.db.one("SELECT last_active FROM sessions WHERE token_hash=?", (h,))["last_active"]
    assert int(time.time()) - la >= 590                   # auto-refresh did not count as activity
    store.db.x("UPDATE sessions SET last_active=? WHERE token_hash=?", (int(time.time()) - 16 * 60, h))
    assert store.session(tok, idle=960) is None
    assert "15 minutes away" in store.expired_reason
    assert not store.db.one("SELECT 1 FROM sessions WHERE token_hash=?", (h,))


def test_account_api(client):
    login(client)
    a = client.get("/api/account").json()
    assert a["user"] == "root" and a["prefs"]["date_style"] == "text" and 30 in a["choices"]["idle_minutes"]
    r = client.put("/api/account/prefs", json={"idle_minutes": 30, "time24": False}, headers=H).json()
    assert r["idle_limit"] == 30 and r["prefs"]["time24"] is False
    me = client.get("/api/me").json()
    assert me["idle_limit"] == 30 and me["prefs"]["time24"] is False
    assert client.put("/api/account/prefs", json={"idle_minutes": 5}, headers=H).status_code == 400
    s = client.get("/api/account/sessions").json()["items"]
    assert len(s) == 1 and s[0]["this"]
    assert client.post("/api/account/sessions/others", headers=H).json()["ended"] == 0
    # idle header beyond the limit: the next request finds the session expired
    from app.state import st
    st.store.db.x("UPDATE sessions SET last_active=?", (int(time.time()) - 31 * 60,))
    r = client.get("/api/me", headers={"X-GWC-Idle": "1900"})
    assert r.status_code == 401 and r.json()["idle"] and "30 minutes away" in r.json()["error"]


def test_password_change_can_keep_other_browsers(client):
    login(client)
    from app.state import st
    uid = st.store.user("root")["id"]
    st.store.create_session(uid, 12)                      # another browser
    r = client.post("/api/account/password", json={"current": "RootPass1234", "new": "NewRootPass9876",
                                                   "sign_out_others": False}, headers=H)
    assert r.status_code == 200
    assert len(st.store.user_sessions(uid)) == 2


def test_activity_search_and_categories(tmp_path):
    a = auditmod.Audit(str(tmp_path / "audit.log"))
    a.log("ameer", "login", "-", True, "", "10.0.0.5")
    a.log("ameer", "server→drain (kept)", "hp:be_shop/s2", True, "saved in haproxy.cfg")
    a.log("ops", "hostname add", "kodje:shop.kodje.my", False, "validate failed")
    a.log("ops", "login", "-", True)
    a.log("ameer", "monitor settings", "monitoring", True)
    r = a.search(hide_logins=True, limit=50)
    assert r["matched"] == 3 and r["hidden_signins"] == 2 and r["items"][0]["action"] == "monitor settings"
    assert [i["cat"] for i in r["items"]] == ["settings", "tunnel", "server"]
    assert a.search(q="haproxy.cfg")["matched"] == 1
    assert a.search(user="ops", result="failed")["items"][0]["target"] == "kodje:shop.kodje.my"
    assert a.search(cat="signin")["matched"] == 2
    page = a.search(limit=2)
    assert len(page["items"]) == 2 and page["more"] and a.search(offset=4, limit=2)["items"][0]["action"] == "login"
    assert a.search(since=int(time.time()) + 10)["matched"] == 0
    assert set(a.search()["users"]) == {"ameer", "ops"}


def test_activity_api_and_csv(client):
    login(client)
    r = client.get("/api/audit?hide_logins=true").json()
    assert r["hidden_signins"] >= 1 and all(i["cat"] != "signin" for i in r["items"])
    csv = client.get("/api/audit.csv?cat=signin").text.splitlines()
    assert csv[0].startswith("time_utc,user,category") and ",root,signin,login," in csv[1]


def test_overview_has_sites_servers_traffic(client):
    login(client)
    d = client.get("/api/overview").json()
    assert {"sites", "servers", "traffic", "settings"} <= set(d) and d["traffic"]["source"] in ("cf", "hp")


def test_localhost_routes_only_match_haproxy_on_the_same_machine():
    cfg = "frontend fe\n    bind *:8080\n    default_backend be\nbackend be\n    server a 10.0.0.9:80\n"
    d = hpcfg.parse(cfg)
    models = {"hp": {"host": "10.0.10.21", "frontends": d["frontends"], "backends": d["backends"], "error": None}}
    # cloudflared on another machine pointing at its own localhost: not this HAProxy
    assert sites.route(models, "x.example", "http://localhost:8080", origin_host="10.0.10.30")["direct"]
    # cloudflared on the HAProxy machine itself
    assert sites.route(models, "x.example", "http://127.0.0.1:8080", origin_host="10.0.10.21")["backend"] == "be"
    assert sites.route(models, "x.example", "http://10.0.10.21:8080", origin_host="10.0.10.30")["frontend"] == "fe"


def test_upgrade_from_v140_database(tmp_path):
    p = str(tmp_path / "v140.db")
    con = sqlite3.connect(p)
    con.executescript(MIGRATIONS[0] + MIGRATIONS[1] + "\nPRAGMA user_version=2;")
    con.execute("INSERT INTO users (username, pw_hash, role, created_at) VALUES ('ameer','x','superadmin',1)")
    con.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen) VALUES ('h',1,1,9999999999,5)")
    con.commit()
    con.close()
    s = Store(DB(p), Vault(str(tmp_path / "k"), create=True))
    assert s.db.version == len(MIGRATIONS) == 3
    assert s.db.one("SELECT last_active FROM sessions")["last_active"] == 5
    assert json.loads(s.db.one("SELECT prefs FROM users")["prefs"]) == {}
