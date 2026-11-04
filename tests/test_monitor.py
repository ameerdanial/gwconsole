"""Tests for v1.4 monitoring and traffic: the database upgrade, Server nodes, Settings → Monitoring,
health parsing, routes (tunnel → HAProxy frontend → backend), monitoring alerts, HAProxy counter
history, Cloudflare traffic parsing, the Traffic and Monitoring APIs, release notes and kept server state."""
import json
import os
import sqlite3
import time

import pytest

from app import api_system, hpcfg, monitor, sites, traffic
from app.db import DB, MIGRATIONS
from app.store import Store
from app.vault import Vault

H = {"X-GWC": "1"}


def login(c):
    assert c.post("/api/login", json={"user": "root", "password": "RootPass1234"}).status_code == 200


def test_upgrade_from_v13_keeps_nodes_and_allows_servers(tmp_path):
    p = str(tmp_path / "old.db")
    con = sqlite3.connect(p)
    con.executescript(MIGRATIONS[0] + "\nPRAGMA user_version=1;")
    con.execute("INSERT INTO nodes (name, kind, data, created_at, updated_at) VALUES ('hp1','haproxy','{\"host\":\"10.0.0.1\"}',1,1)")
    con.commit()
    con.close()
    s = Store(DB(p), Vault(str(tmp_path / "k"), create=True))
    assert s.db.version == len(MIGRATIONS)
    assert [n.host for n in s.nodes("haproxy")] == ["10.0.0.1"]
    from app.config import ServerNode
    s.save_node("server", ServerNode(name="kodje-web", host="10.0.20.11"))
    assert [n.name for n in s.nodes("server")] == ["kodje-web"]
    s.db.x("INSERT INTO services (node, unit, created_at) VALUES ('kodje-web','nginx.service',1)")
    s.save_node("server", ServerNode(name="web1", host="10.0.20.11"), old_name="kodje-web")
    assert s.db.one("SELECT node FROM services")["node"] == "web1"
    s.delete_node("web1")
    assert not s.db.q("SELECT * FROM services")
    s.db.close()


def test_monitor_settings_validation(store):
    m = store.monitor_cfg()
    assert m["check_every"] == 60 and m["summary_tz"] == "Asia/Kuala_Lumpur"
    m = store.set_monitor({"disk_warn": "75", "summary_time": "08:30", "summary_telegram": "false"})
    assert m["disk_warn"] == 75 and m["summary_time"] == "08:30" and m["summary_telegram"] is False
    for bad in ({"check_every": 5}, {"summary_time": "25:00"}, {"summary_tz": "Mars/Base"},
                {"disk_warn": 95, "disk_crit": 90}, {"nope": 1}):
        with pytest.raises(ValueError):
            store.set_monitor(bad)


def test_parse_health():
    text = """@@CORES
4
@@LOAD
1.24 0.98 0.80 2/345 999
@@MEM
MemTotal:        8000000 kB
MemAvailable:    3120000 kB
@@DISK
/dev/sda1 100000 41000 59000 41% /
/dev/sdb1 200000 166000 34000 83% /var
/dev/sda2 1000 900 100 90% /boot
@@UP
261234.55
@@OS
Debian GNU/Linux 13 (trixie)
@@SVC
nginx.service active
redis-server.service inactive
"""
    h = monitor.parse_health(text)
    assert h["cores"] == 4 and h["load"][0] == 1.24
    assert h["mem_pct"] == 61.0
    assert h["fullest"] == {"mount": "/var", "size": 200000 * 1024, "pct": 83.0}     # /boot ignored
    assert h["uptime"] == 261234 and h["os"].startswith("Debian")
    assert h["services"] == {"nginx.service": "active", "redis-server.service": "inactive"}


CFG = """global
    stats socket /run/haproxy/admin.sock mode 660 level admin
defaults
    mode http
frontend fe_https
    bind *:8080
    acl h_kodje hdr(host) -i kodje.adproject.fun app.kodje.my
    use_backend be_kodje if h_kodje
    use_backend be_blog if { hdr(host) -i blog.adproject.fun }
    default_backend be_web
frontend mc_front
    mode tcp
    bind 10.0.10.21:25565
    default_backend be_mc
backend be_kodje
    server k1 10.0.20.11:80 check
    server k2 10.0.20.12:80 check weight 5
backend be_blog
    server b1 10.0.20.20:80 check
backend be_web
    server w1 10.0.20.30:80 check
backend be_mc
    mode tcp
    server m1 10.0.30.15:25565 check
"""


def _models():
    d = hpcfg.parse(CFG)
    return {"haproxy-lab": {"host": "10.0.10.21", "frontends": d["frontends"], "backends": d["backends"], "error": None}}


def test_routes_through_haproxy():
    m = _models()
    r = sites.route(m, "kodje.adproject.fun", "http://10.0.10.21:8080")
    assert (r["hp_node"], r["frontend"], r["backend"], r["how"], r["direct"]) == ("haproxy-lab", "fe_https", "be_kodje", "rule", False)
    assert sites.route(m, "blog.adproject.fun", "http://10.0.10.21:8080")["backend"] == "be_blog"
    assert sites.route(m, "www.adproject.fun", "http://10.0.10.21:8080")[("how")] == "default"
    r = sites.route(m, "mc.adproject.fun", "tcp://10.0.10.21:25565")
    assert (r["kind"], r["frontend"], r["backend"]) == ("tcp", "mc_front", "be_mc")
    r = sites.route(m, "sw.adproject.fun", "http://10.0.20.40:80")
    assert r["direct"] and not r["frontend"]
    assert sites.route(m, "x", "http_status:404")["kind"] == "other"
    hp = [{"node": "haproxy-lab", "backends": [{"name": "be_kodje", "servers": [
        {"status": "UP"}, {"status": "DOWN"}]}]}]
    assert sites.servers_up(hp, "haproxy-lab", "be_kodje") == (1, 2)


def test_kept_server_state_edits_one_line():
    t = hpcfg.set_server_flags(CFG, "be_kodje", "k2", weight="0")
    t = hpcfg.set_server_flags(t, "be_kodje", "k1", disabled=True)
    f = hpcfg.server_flags(t)
    assert f["be_kodje/k1"] == {"disabled": True, "weight": ""} and f["be_kodje/k2"]["weight"] == "0"
    diff = [l for l in t.splitlines() if l not in CFG.splitlines()]
    assert diff == ["    server k1 10.0.20.11:80 check disabled", "    server k2 10.0.20.12:80 check weight 0"]
    back = hpcfg.set_server_flags(hpcfg.set_server_flags(t, "be_kodje", "k1", disabled=False), "be_kodje", "k2", weight="5")
    assert back == CFG
    with pytest.raises(hpcfg.CfgError):
        hpcfg.set_server_flags(CFG, "be_kodje", "nope", disabled=True)


def test_monitoring_alerts_and_api(client):
    from app.state import st
    login(client)
    db = st.store.db
    t = int(time.time())
    db.x("INSERT INTO nodes (name, kind, data, created_at, updated_at) VALUES ('kodje-redis','server',?,1,1)",
         (json.dumps({"host": "10.0.20.15"}),))
    st.s = st.store.runtime(st.base)
    db.x("INSERT INTO services (node, unit, created_at) VALUES ('kodje-redis','redis-server.service',1)")
    h = {"cores": 1, "load": [0.1, 0.1, 0.1], "mem_pct": 18.0, "fullest": {"mount": "/var", "pct": 91.0},
         "services": {"redis-server.service": "inactive"}}
    db.x("INSERT INTO health (node, data, at) VALUES ('kodje-redis', ?, ?)", (json.dumps(h), t))
    state = {"status": "down", "pub": {"ok": False, "code": 502, "ms": 80, "err": "HTTP 502", "fails": 3}}
    db.x("INSERT INTO checks (host, kind, source, internal, opts, state, created_at) VALUES (?,?,?,?,?,?,?)",
         ("blog.adproject.fun", "http", "tunnel", "http://10.0.10.21:8080", '{"public": true}', json.dumps(state), t))
    monitor.add_samples([("site.pub.up:blog.adproject.fun", t - 120, 1.0), ("site.pub.up:blog.adproject.fun", t - 60, 0.0)])
    alerts, unknown = st.monitor.alerts()
    kinds = {a["kind"]: a for a in alerts}
    assert kinds["site.down"]["sev"] == "crit" and kinds["srv.disk"]["sev"] == "crit"
    assert kinds["svc.stopped"]["where"] == "kodje-redis / redis-server.service"
    assert not unknown
    r = client.get("/api/monitor").json()
    assert r["kpi"]["sites_total"] == 1 and r["kpi"]["down"] == ["blog.adproject.fun"]
    assert r["sites"][0]["uptime24"] == 50.0
    assert r["servers"][0]["watched"] == [{"unit": "redis-server.service", "state": "inactive"}]
    # site options and "don't check"
    assert client.put("/api/monitor/sites/blog.adproject.fun", json={"path": "health", "excluded": True},
                      headers=H).status_code == 400
    assert client.put("/api/monitor/sites/blog.adproject.fun", json={"path": "/health", "excluded": True},
                      headers=H).json()["ok"]
    assert client.get("/api/admin/monitor").json()["excluded"] == ["blog.adproject.fun"]
    assert client.delete("/api/monitor/sites/blog.adproject.fun", headers=H).status_code == 400   # auto: exclude only
    assert client.put("/api/admin/monitor", json={"disk_warn": 70}, headers=H).json()["settings"]["disk_warn"] == 70
    s = client.get("/api/monitor/series?names=site.pub.up:blog.adproject.fun&range=1h").json()
    assert len(s["series"]["site.pub.up:blog.adproject.fun"]) == 2


def test_haproxy_counters_to_history(client):
    from app.state import st
    m = st.monitor

    def snap(req, e5, conns):
        return [{"node": "hp", "info": {"CurrConns": conns}, "frontends": [
            {"name": "fe_https", "mode": "http", "req_tot": req, "stot": 1, "hrsp_4xx": 0, "hrsp_5xx": 0, "bin": req, "bout": 0}],
            "backends": [{"name": "be_blog", "mode": "http", "req_tot": req, "stot": 1, "hrsp_4xx": 0,
                          "hrsp_5xx": e5, "bin": 0, "bout": 0, "servers": []}]}]
    m.record_haproxy(snap(1000, 10, 5))        # first sight: baseline only
    m.record_haproxy(snap(1100, 30, 9))        # +100 requests, +20 5xx
    m.record_haproxy(snap(40, 2, 3))           # HAProxy restarted: counters start again
    m.hp_minute -= 60                          # pretend a minute passed
    m.record_haproxy(snap(40, 2, 3))
    rows = {r["name"]: r for r in st.store.db.q("SELECT * FROM traffic_daily WHERE source='hp'")}
    assert rows["hp/fe:fe_https"]["requests"] == 140 and rows["hp/be:be_blog"]["s5xx"] == 22
    cfg = st.store.set_monitor({"err5xx_min": 50, "err5xx_pct": 5})
    alerts, _ = m.alerts()
    assert any(a["kind"] == "hp.5xx" and a["where"] == "hp / be_blog" for a in alerts)
    assert cfg["err5xx_pct"] == 5


def test_cloudflare_traffic_parsing_and_report(client):
    from app.state import st
    login(client)
    day = monitor.local_day(time.time(), st.store.monitor_cfg())
    traffic.Collector.store_hosts(day, {"viewer": {"zones": [{
        "hosts": [
            {"count": 900, "sum": {"edgeResponseBytes": 9000, "visits": 300},
             "dimensions": {"clientRequestHTTPHost": "Kodje.adproject.fun", "edgeResponseStatus": 200, "cacheStatus": "hit"}},
            {"count": 100, "sum": {"edgeResponseBytes": 100, "visits": 10},
             "dimensions": {"clientRequestHTTPHost": "kodje.adproject.fun", "edgeResponseStatus": 502, "cacheStatus": "dynamic"}},
            {"count": 50, "sum": {"edgeResponseBytes": 50, "visits": 5},
             "dimensions": {"clientRequestHTTPHost": "shop.adproject.fun", "edgeResponseStatus": 404, "cacheStatus": "miss"}}],
        "countries": [{"count": 700, "dimensions": {"clientRequestHTTPHost": "kodje.adproject.fun", "clientCountryName": "MY"}},
                      {"count": 300, "dimensions": {"clientRequestHTTPHost": "kodje.adproject.fun", "clientCountryName": "SG"}}]}]}})
    traffic.Collector.store_zone("adproject.fun", {"viewer": {"zones": [{"days": [
        {"dimensions": {"date": day}, "uniq": {"uniques": 420},
         "sum": {"requests": 1050, "bytes": 9150, "cachedRequests": 900, "threats": 7,
                 "countryMap": [{"clientCountryName": "MY", "requests": 700}],
                 "responseStatusMap": [{"edgeResponseStatus": 200, "requests": 900},
                                       {"edgeResponseStatus": 502, "requests": 100}]}}]}]}})
    r = client.get("/api/traffic?range=7d").json()
    k = r["cf"]["hosts"][0]
    assert (k["name"], k["requests"], k["cached"], k["s5xx"], k["countries"]) == ("kodje.adproject.fun", 1000, 900, 100, ["MY", "SG"])
    assert r["cf"]["kpi"]["visitors"]["value"] == 420 and r["cf"]["kpi"]["threats"]["value"] == 7
    assert r["cf"]["kpi"]["cached"]["value"] == round(900 * 100 / 1050, 1)
    assert [s["name"] for s in r["cf"]["chart"]["series"]] == ["kodje.adproject.fun", "shop.adproject.fun"]
    csv = client.get("/api/traffic.csv?range=7d").text
    assert csv.splitlines()[1].startswith("kodje.adproject.fun,1000,310,9100,900,0,100,MY SG")


def test_release_notes_parse():
    rel = api_system.changelog()
    v = {r["version"]: r for r in rel}
    assert v["1.0.0"]["type"] == "first" and v["1.0.0"]["summary"] == "Initial release"
    assert v["1.3.0"]["type"] == "minor" and v["1.3.0"]["counts"]["added"] >= 5
    assert "Add sites and edit HAProxy without typing config" in v["1.3.0"]["summary"]


def test_server_node_api(client):
    login(client)
    r = client.post("/api/admin/nodes", headers=H, json={
        "kind": "server", "name": "kodje-web", "host": "10.0.20.11", "user": "root",
        "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"})
    assert r.json()["ok"]
    kinds = {n["name"]: n["kind"] for n in client.get("/api/admin/nodes").json()["items"]}
    assert kinds == {"kodje-web": "server"}
    assert [s["name"] for s in client.get("/api/monitor").json()["servers"]] == ["kodje-web"]


def test_helper_records_update_history(tmp_path, monkeypatch, client):
    from app import helper
    monkeypatch.setattr(helper, "STATE", str(tmp_path))
    monkeypatch.setattr(os, "chown", lambda *a: None)
    for i in range(55):
        helper.record(kind="upgrade", **{"from": "v1.3.0", "to": "v1.4.0"}, by="ameer", result="done", seconds=i)
    lines = (tmp_path / "history.jsonl").read_text().splitlines()
    assert len(lines) == 50 and json.loads(lines[-1])["seconds"] == 54
    monkeypatch.setattr(api_system, "STATE_DIR", str(tmp_path))
    h = api_system.update_history()
    assert h[0]["to"] == "v1.4.0" and h[0]["by"] == "ameer"
    # the start-up record of the same upgrade is not listed twice
    assert sum(1 for x in h if str(x.get("to")).lstrip("v") == "1.4.0" and x.get("by") == "installer") == 0
