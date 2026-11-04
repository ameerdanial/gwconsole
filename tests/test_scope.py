"""Tests for v1.5 scoped access: domain matching, what a scope gives on HAProxy (own / shared backends,
own host rules), rebuilding a scoped user's ops so other rules stay untouched, the safety-net check on
the parsed config, storing scopes, filters for tunnels / alerts / activity, and a check that every
mutating API route checks the role and the scope."""
import inspect
import sqlite3

import pytest

from app import audit as auditmod
from app import hpcfg
from app.db import DB, MIGRATIONS
from app.scope import HPView, Scope, ScopeError, domain_matches
from app.sites import filter_tunnels
from app.store import Store
from app.vault import Vault

CFG = """global
    log /dev/log local0

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend fe_https
    bind :443
    acl host_kodje hdr(host) -i kodje.adproject.fun
    acl host_api hdr(host) -i api.kodje.my app.kodje.my
    acl host_shop hdr(host) -i shop.adproject.fun
    use_backend be_kodje if host_kodje
    use_backend be_kodje if host_api
    use_backend be_shop if host_shop
    default_backend be_web

frontend mc_front
    mode tcp
    bind :25565
    default_backend be_mc

backend be_web
    server web1 10.0.20.11:80 check

backend be_kodje
    server kodje-web 10.0.20.11:80 check

backend be_shop
    server shop1 10.0.20.21:80 check

backend be_mc
    mode tcp
    server mc1 10.0.30.15:25565 check
"""


def kodje(**kw) -> Scope:
    return Scope(all=False, user="kodje-ops", tunnels={("cfd-lab", "kodje")}, domains=["*.kodje.my", "kodje.my",
                 "kodje.adproject.fun"], **kw)


@pytest.mark.parametrize("pattern,host,ok", [
    ("kodje.my", "kodje.my", True), ("kodje.my", "api.kodje.my", False),
    ("*.kodje.my", "api.kodje.my", True), ("*.kodje.my", "a.b.kodje.my", True), ("*.kodje.my", "kodje.my", False),
    ("*.kodje.my", "kodje.my.evil.net", False), ("*.kodje.my", "evilkodje.my", False), ("*.kodje.my", "API.Kodje.MY.", True),
    ("kodje.adproject.fun", "www.adproject.fun", False), ("", "x.my", False),
])
def test_domain_matching_is_exact(pattern, host, ok):
    assert domain_matches(pattern, host) is ok


def test_hp_view_own_and_shared_backends():
    m = hpcfg.parse(CFG)
    routes = [{"host": "www.kodje.my", "hp_node": "hp1", "frontend": "fe_https", "backend": "be_web"}]
    v = HPView(kodje(), "hp1", m, routes)
    assert v.own_backends == {"be_kodje"}                  # only kodje hostnames reach it
    assert v.shared_backends == {"be_web"}                 # default backend that www.kodje.my lands on
    assert "be_shop" not in v.shared_backends and not v.backend_visible("be_mc")
    assert v.frontends == {"fe_https"} and len(v.own_rules["fe_https"]) == 2
    f = v.filter_model(m)
    fe = f["frontends"][0]
    assert {r["value"] for r in fe["rules"]} == {"kodje.adproject.fun", "api.kodje.my app.kodje.my"}
    assert fe["locked"] and fe["advanced"] == ""
    assert {b["name"]: b["locked"] for b in f["backends"]} == {"be_web": True, "be_kodje": False}
    # an extra backend picked explicitly
    v2 = HPView(kodje(backends={("hp1", "be_mc")}), "hp1", m, [])
    assert "be_mc" in v2.own_backends


def test_scoped_rule_edit_keeps_every_other_rule():
    m = hpcfg.parse(CFG)
    v = HPView(kodje(), "hp1", m, [])
    mine = v.filter_model(m)["frontends"][0]
    rules = [r for r in mine["rules"] if r["value"] != "kodje.adproject.fun"]      # drop one of my rules …
    rules.append({"cond": "host", "value": "new.kodje.my", "action": "backend", "target": "be_kodje"})  # … add one
    ops = [{"op": "upsert", "kind": "frontend", "orig_name": "fe_https", "model": {**mine, "rules": rules}}]
    new = hpcfg.apply_ops(CFG, v.rewrite_ops(m, ops))
    v.check_change(m, hpcfg.parse(new))
    assert "shop.adproject.fun" in new and "default_backend be_web" in new and "new.kodje.my" in new
    assert "kodje.adproject.fun" not in new and "bind :443" in new


@pytest.mark.parametrize("bad", [
    {"cond": "host", "value": "shop.adproject.fun", "action": "backend", "target": "be_kodje"},   # someone else's host
    {"cond": "host", "value": "x.kodje.my evil.com", "action": "backend", "target": "be_kodje"},  # mixed hosts
    {"cond": "path", "value": "/api", "action": "backend", "target": "be_kodje"},                 # not a host rule
    {"cond": "host", "value": "x.kodje.my", "action": "backend", "target": "be_mc"},              # not their backend
])
def test_scoped_rule_outside_scope_refused(bad):
    m = hpcfg.parse(CFG)
    v = HPView(kodje(), "hp1", m, [])
    mine = v.filter_model(m)["frontends"][0]
    with pytest.raises(ScopeError):
        v.rewrite_ops(m, [{"op": "upsert", "kind": "frontend", "orig_name": "fe_https",
                           "model": {**mine, "rules": mine["rules"] + [bad]}}])


def test_scoped_backend_and_frontend_changes():
    m = hpcfg.parse(CFG)
    v = HPView(kodje(), "hp1", m, [{"host": "www.kodje.my", "hp_node": "hp1", "frontend": "fe_https", "backend": "be_web"}])
    be = next(b for b in m["backends"] if b["name"] == "be_kodje")
    srv = be["servers"] + [{**be["servers"][0], "_key": "", "name": "kodje-2", "addr": "10.0.20.12:80"}]
    ops = v.rewrite_ops(m, [{"op": "upsert", "kind": "backend", "orig_name": "be_kodje", "model": {**be, "servers": srv}}])
    v.check_change(m, hpcfg.parse(hpcfg.apply_ops(CFG, ops)))                  # their own backend: fine
    web = next(b for b in m["backends"] if b["name"] == "be_web")
    for op in ({"op": "upsert", "kind": "backend", "orig_name": "be_web", "model": web},       # shared → locked
               {"op": "delete", "kind": "backend", "name": "be_shop"},
               {"op": "delete", "kind": "frontend", "name": "mc_front"},
               {"op": "upsert", "kind": "frontend", "model": {"name": "fe_new", "binds": [{"addr": ":81"}]}}):
        with pytest.raises(ScopeError):
            v.rewrite_ops(m, [op])
    # safety net: even if crafted ops got through, changing someone else's backend or a bind is refused
    with pytest.raises(ScopeError, match="shared"):
        v.check_change(m, hpcfg.parse(CFG.replace("web1 10.0.20.11:80", "web1 10.6.6.6:80")))
    with pytest.raises(ScopeError, match="locked"):
        v.check_change(m, hpcfg.parse(CFG.replace("bind :443", "bind :8443")))
    with pytest.raises(ScopeError):
        v.check_change(m, hpcfg.parse(CFG.replace("shop.adproject.fun", "shop2.adproject.fun")))


def test_unscoped_sees_and_changes_everything():
    m = hpcfg.parse(CFG)
    v = HPView(Scope(all=True), "hp1", m, [])
    assert v.filter_model(m) is m and v.backend_ok("be_web")
    v.check_change(m, hpcfg.parse(CFG.replace("bind :443", "bind :8443")))


def test_store_scope_validation(store):
    op = store.create_user("kodje-ops", "OpsPass12345", "operator", must_change=False)
    adm = store.create_user("adm2", "OpsPass12345", "superadmin", must_change=False)
    r = store.set_scope(op, "pick", [{"kind": "domain", "ref": "*.Kodje.MY."}, {"kind": "tunnel", "ref": "cfd-lab/kodje"},
                                     {"kind": "domain", "ref": "*.kodje.my"}])
    assert r["after"]["items"] == [{"kind": "domain", "ref": "*.kodje.my"}, {"kind": "tunnel", "ref": "cfd-lab/kodje"}]
    assert {u["username"]: u["scope_mode"] for u in store.users()}["kodje-ops"] == "pick"
    for bad in ([{"kind": "domain", "ref": "kodje"}], [{"kind": "domain", "ref": "a b.my"}], [{"kind": "tunnel", "ref": "x"}],
                [{"kind": "nope", "ref": "a/b"}], []):
        with pytest.raises(ValueError):
            store.set_scope(op, "pick", bad)
    with pytest.raises(ValueError, match="superadmin"):
        store.set_scope(adm, "pick", [{"kind": "domain", "ref": "x.my"}])
    store.set_role(op, "superadmin")                       # promoting clears the scope
    assert store.user_by_id(op)["scope_mode"] == "all" and not store.scope_items(op)


def test_filter_tunnels_and_text_targets():
    data = {"nodes": [{"node": "cfd-lab", "tunnels": [
        {"name": "kodje", "config": {"ingress": [{"hostname": "api.kodje.my"}, {"hostname": None}]}},
        {"name": "adproject", "config": {"ingress": [{"hostname": "www.adproject.fun"}, {"hostname": "kodje.adproject.fun"}]},
         "dns": {"routes": [{"hostname": "www.adproject.fun"}, {"hostname": "kodje.adproject.fun"}], "orphans": []}},
        {"name": "sw-tunnel", "config": {"ingress": [{"hostname": "selatwave.com.my"}]}}]}],
        "unmanaged": [{"id": "x"}], "accounts": {"main": {}}}
    out = filter_tunnels(kodje(), data)
    ts = {t["name"]: t for t in out["nodes"][0]["tunnels"]}
    assert set(ts) == {"kodje", "adproject"} and ts["kodje"]["scope"] == "full" and ts["adproject"]["scope"] == "routes"
    assert [r["hostname"] for r in ts["adproject"]["config"]["ingress"]] == ["kodje.adproject.fun"]
    assert [r["hostname"] for r in ts["adproject"]["dns"]["routes"]] == ["kodje.adproject.fun"]
    assert out["unmanaged"] == [] and out["accounts"] == {}
    sc = kodje()
    assert sc.text_ok("api.kodje.my") and sc.text_ok("cfd-lab:kodje") and not sc.text_ok("cfd-lab:adproject")
    assert not sc.text_ok("shop.adproject.fun") and not sc.text_ok("haproxy-lab")


def test_activity_scoped_filter(tmp_path):
    a = auditmod.Audit(str(tmp_path / "audit.log"))
    a.log("ameer", "hostname add", "cfd-lab:adproject:shop.adproject.fun", True)
    a.log("ameer", "hostname add", "cfd-lab:kodje:api.kodje.my", True)
    a.log("kodje-ops", "login", "-", True)
    sc = kodje()
    r = a.search(allow=lambda e: e.get("user") == sc.user or sc.text_ok(e.get("target", "")))
    assert [i["target"] for i in r["items"]] == ["-", "cfd-lab:kodje:api.kodje.my"]
    assert sorted(r["users"]) == ["ameer", "kodje-ops"]


def test_migration_4_keeps_upgraded_installs_unlocked(tmp_path):
    p = str(tmp_path / "v141.db")
    con = sqlite3.connect(p)
    con.executescript("".join(MIGRATIONS[:3]) + "\nPRAGMA user_version=3;")
    con.execute("INSERT INTO users (username, pw_hash, role, created_at) VALUES ('ameer','x','superadmin',1)")
    con.commit()
    con.close()
    s = Store(DB(p), Vault(str(tmp_path / "k"), create=True))
    assert s.general()["twofa_required"] == "nobody"           # upgraded: nobody is forced into 2FA
    assert s.user("ameer")["scope_mode"] == "all"
    s.db.close()
    fresh = Store(DB(str(tmp_path / "new.db")), Vault(str(tmp_path / "k2"), create=True))
    assert fresh.general()["twofa_required"] == "superadmin"    # new install: superadmins must use 2FA
    fresh.db.close()


# every route that changes something must check the role (need) and, unless it's superadmin-only, the scope
EXEMPT = {"/api/login", "/api/logout", "/api/login/2fa", "/api/whatsnew/seen",
          "/api/account/prefs", "/api/account/password", "/api/account/sessions/{sid}", "/api/account/sessions/others",
          "/api/account/2fa/start", "/api/account/2fa/confirm", "/api/account/2fa/off", "/api/account/2fa/recovery",
          "/api/account/2fa/browsers", "/api/monitor/run", "/api/alerts/check", "/api/haproxy/{node}/probe",
          "/api/cfg/{kind}/{ref}/diff", "/api/tunnels/{node}/{tunnel}/test"}


def test_every_mutating_route_checks_role_and_scope():
    from app.main import app
    missing = []
    for r in app.routes:
        methods = getattr(r, "methods", set()) or set()
        if not methods & {"POST", "PUT", "PATCH", "DELETE"} or r.path in EXEMPT:
            continue
        src = inspect.getsource(r.endpoint)
        if 'need(request, "superadmin")' in src:
            continue
        if "need(request" not in src or not any(k in src for k in ("scope(request)", "_cfg_scope(", "_scoped(",
                                                                   "_need_node(", "_mine(", "_mute_ok(")):
            missing.append(f"{sorted(methods)[0]} {r.path}")
    assert not missing, missing


def test_access_choices_fall_back_to_monitoring_routes(client):
    """With the tunnel and HAProxy nodes out of reach, the Access dialog still offers what Monitoring found."""
    import json
    import time

    from app import scope as scopemod
    from app.state import st
    client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    route = {"tunnel": {"node": "cfd-1", "name": "kodje"}, "hp_node": "hp-1", "backend": "be_kodje"}
    st.store.db.x("INSERT INTO checks (host, kind, source, internal, route, opts, seen_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
                  ("app.kodje.my", "http", "auto", 0, json.dumps(route), "{}", int(time.time()), int(time.time())))
    scopemod.forget()
    ch = client.get("/api/admin/scope/choices").json()
    assert [(t["ref"], t["hosts"], t["offline"]) for t in ch["tunnels"]] == [("cfd-1/kodje", ["app.kodje.my"], True)]
    assert [(b["ref"], b["hosts"]) for b in ch["backends"]] == [("hp-1/be_kodje", ["app.kodje.my"])]
    assert ch["zones"] == [{"zone": "kodje.my", "hosts": ["app.kodje.my"]}]


def test_zone_guess_for_two_part_endings():
    from app.api_admin import _guess_zone
    assert _guess_zone("shop.example.com") == "example.com"
    assert _guess_zone("app.sw.com.my") == "sw.com.my" and _guess_zone("a.b.co.uk") == "b.co.uk"
    assert _guess_zone("x.example.my") == "example.my"
