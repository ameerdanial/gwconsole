"""Tests for the HAProxy config model behind the Add / Edit forms: parsing into fields, keeping
unknown lines, merging edits in place, references, and validation."""
import copy

import pytest

from app import hpcfg

CFG = """global
    log /dev/log local0
    stats socket /run/haproxy/admin.sock mode 660 level admin

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# public web entry
frontend fe_web
    bind *:80
    option httplog   # keep access logs
    acl host_kodje hdr(host) -i kodje.adproject.fun
    acl is_api path_beg /api
    acl bad_bot hdr(User-Agent) -i badbot
    http-request deny if bad_bot
    http-request set-header X-Forwarded-Proto http
    use_backend be_kodje if host_kodje
    use_backend be_api if is_api
    use_backend be_mc if { req.ssl_sni -i mc.example.com } or { src 1.2.3.4 }
    default_backend be_default

backend be_kodje
    balance roundrobin
    option httpchk GET /up
    http-check expect status 200-399
    option forwardfor
    timeout server 1m
    stick-table type string len 32 size 1k   # not managed
    server web1 10.0.20.11:80 check weight 100
    server web2 10.0.20.12:80 check weight 100 inter 2s
    server dr1 10.8.20.11:80 check backup

backend be_api
    server api1 10.0.20.30:8080 check

backend be_default
    http-request return status 404

backend be_mc
    mode tcp
    server mc 10.0.30.15:25565 check
"""


def model(text, kind, name):
    return copy.deepcopy(hpcfg.find_section(text, kind, name))


def upsert(text, kind, m, orig=None):
    return hpcfg.apply_ops(text, [{"op": "upsert", "kind": kind, "orig_name": orig if orig is not None else m["name"], "model": m}])


def test_parse_fields_and_advanced():
    fe = model(CFG, "frontend", "fe_web")
    assert [b["addr"] for b in fe["binds"]] == ["*:80"] and fe["log"] is True
    assert [(r["cond"], r["value"], r["action"], r["target"]) for r in fe["rules"]] == [
        ("header", "badbot", "deny", ""), ("host", "kodje.adproject.fun", "backend", "be_kodje"),
        ("path_beg", "/api", "backend", "be_api")]
    assert fe["rules"][0]["hname"] == "User-Agent"
    assert fe["headers"] == [{"_key": "hdr:0", "dir": "request", "name": "X-Forwarded-Proto", "value": "http"}]
    assert fe["default_backend"] == "be_default"
    # a combined condition isn't a simple rule: kept verbatim
    assert fe["advanced"] == "use_backend be_mc if { req.ssl_sni -i mc.example.com } or { src 1.2.3.4 }"
    be = model(CFG, "backend", "be_kodje")
    assert be["balance"] == "roundrobin" and be["forwardfor"] and be["timeouts"]["server"] == "1m"
    assert be["health"]["type"] == "http" and be["health"]["path"] == "/up" and be["health"]["expect"] == "200-399"
    assert [(s["name"], s["addr"], s["check"], s["backup"], s["inter"]) for s in be["servers"]] == [
        ("web1", "10.0.20.11:80", True, False, ""), ("web2", "10.0.20.12:80", True, False, "2s"),
        ("dr1", "10.8.20.11:80", True, True, "")]
    assert "stick-table type string len 32 size 1k   # not managed" in be["advanced"]


@pytest.mark.parametrize("kind,name", [("frontend", "fe_web"), ("backend", "be_kodje"), ("backend", "be_api"),
                                       ("backend", "be_default"), ("backend", "be_mc")])
def test_saving_unchanged_changes_nothing(kind, name):
    assert upsert(CFG, kind, model(CFG, kind, name)) == CFG


def test_edit_in_place_keeps_order_comments_and_unknown_lines():
    be = model(CFG, "backend", "be_kodje")
    be["servers"][1]["addr"] = "10.0.20.99:80"
    be["servers"].append({**hpcfg.empty_server(), "name": "web3", "addr": "10.0.20.13:80"})
    be["timeouts"]["server"] = "2m"
    new = upsert(CFG, "backend", be)
    sec = new.split("\nbackend be_kodje")[1].split("\nbackend be_api")[0]
    assert "    server web2 10.0.20.99:80 check inter 2s weight 100\n" in sec
    assert sec.index("server dr1") < sec.index("server web3")          # added after the others
    assert "timeout server 2m" in sec and "timeout server 1m" not in sec
    assert "stick-table type string len 32 size 1k   # not managed" in sec
    # nothing outside the section moved
    assert new.split("\nbackend be_kodje")[0] == CFG.split("\nbackend be_kodje")[0]


def test_add_rule_to_existing_frontend_and_new_backend():
    be = hpcfg.empty_backend()
    be.update(name="be_shop", servers=[{**hpcfg.empty_server(), "name": "s1", "addr": "10.0.40.5:80"}],
              health={"type": "http", "method": "GET", "path": "/health", "host": "", "expect": "200"})
    fe = model(CFG, "frontend", "fe_web")
    fe["rules"].append({"cond": "host", "value": "shop.example.com", "action": "backend", "target": "be_shop"})
    new = hpcfg.apply_ops(CFG, [{"op": "upsert", "kind": "backend", "model": be},
                                {"op": "upsert", "kind": "frontend", "orig_name": "fe_web", "model": fe}])
    fe_sec = new.split("frontend fe_web")[1].split("\nbackend be_kodje")[0]
    assert "    acl gwc_host_shop_example_com hdr(host) -i shop.example.com\n" in fe_sec
    # the new use_backend joins the other use_backend lines, before default_backend
    assert fe_sec.index("use_backend be_api if is_api") < fe_sec.index("use_backend be_shop if gwc_host_shop_example_com") \
        < fe_sec.index("default_backend")
    assert "option httplog   # keep access logs" in fe_sec
    tail = new.split("\nbackend be_shop")[1]
    assert "option httpchk\n    http-check send meth GET uri /health\n    http-check expect status 200" in tail
    assert "server s1 10.0.40.5:80 check" in tail
    assert hpcfg.find_section(new, "backend", "be_shop")["servers"][0]["addr"] == "10.0.40.5:80"


def test_remove_rule_removes_its_acl_too():
    fe = model(CFG, "frontend", "fe_web")
    fe["rules"] = [r for r in fe["rules"] if r["value"] != "/api"]
    new = upsert(CFG, "frontend", fe)
    assert "is_api" not in new and "use_backend be_kodje if host_kodje" in new


def test_reorder_rules():
    fe = model(CFG, "frontend", "fe_web")
    fe["rules"][1], fe["rules"][2] = fe["rules"][2], fe["rules"][1]
    new = upsert(CFG, "frontend", fe)
    assert new.index("use_backend be_api if is_api") < new.index("use_backend be_kodje if host_kodje")


def test_advanced_edit_and_section_keyword_refused():
    be = model(CFG, "backend", "be_default")
    be["advanced"] = "http-request return status 410"
    assert "http-request return status 410" in upsert(CFG, "backend", be)
    be["advanced"] = "backend sneaky"
    with pytest.raises(hpcfg.CfgError, match="new section"):
        upsert(CFG, "backend", be)


def test_rename_backend_updates_references():
    be = model(CFG, "backend", "be_api")
    be["name"] = "be_api_v2"
    new = upsert(CFG, "backend", be, orig="be_api")
    assert "backend be_api_v2" in new and "use_backend be_api_v2 if is_api" in new and "be_api\n" not in new


def test_delete_is_blocked_while_referenced():
    with pytest.raises(hpcfg.CfgError, match="still used by frontend fe_web"):
        hpcfg.apply_ops(CFG, [{"op": "delete", "kind": "backend", "name": "be_api"}])
    fe = model(CFG, "frontend", "fe_web")
    fe["rules"] = [r for r in fe["rules"] if r.get("target") != "be_api"]
    new = hpcfg.apply_ops(CFG, [{"op": "upsert", "kind": "frontend", "orig_name": "fe_web", "model": fe},
                                {"op": "delete", "kind": "backend", "name": "be_api"}])
    assert "be_api" not in new and "backend be_default" in new
    # deleting a frontend takes its comment block with it
    new2 = hpcfg.apply_ops(CFG, [{"op": "delete", "kind": "frontend", "name": "fe_web"}])
    assert "# public web entry" not in new2 and "frontend" not in new2


def test_new_tcp_frontend_with_sni_rules():
    fe = hpcfg.empty_frontend("tcp")
    fe.update(name="fe_tls", binds=[{"addr": "*:443"}],
              rules=[{"cond": "sni", "value": "mc.example.com", "action": "backend", "target": "be_mc"}],
              default_backend="be_mc")
    new = hpcfg.apply_ops(CFG, [{"op": "upsert", "kind": "frontend", "model": fe}])
    sec = new.split("frontend fe_tls")[1].split("\nbackend be_kodje")[0]
    assert "mode tcp" in sec and "option tcplog" in sec and "tcp-request inspect-delay 5s" in sec
    assert "acl gwc_sni_mc_example_com req.ssl_sni -i mc.example.com" in sec
    # new frontends are placed after the last frontend
    assert new.index("frontend fe_tls") < new.index("\nbackend be_kodje")
    assert hpcfg.find_section(new, "frontend", "fe_tls")["rules"][0]["cond"] == "sni"


def test_https_ratelimit_force_https_roundtrip():
    fe = hpcfg.empty_frontend()
    fe.update(name="fe_s", binds=[{"addr": "*:443", "ssl": True, "crt": "/etc/haproxy/certs/", "h2": True}],
              force_https=True, ratelimit="100", default_backend="be_api",
              rules=[{"cond": "path_beg", "value": "/admin", "action": "allow_only", "target": "192.168.10.0/24"},
                     {"cond": "host", "value": "old.example.com", "action": "redirect", "target": "https://new.example.com"}])
    new = hpcfg.apply_ops(CFG, [{"op": "upsert", "kind": "frontend", "model": fe}])
    assert "bind *:443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1" in new
    assert "http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }" in new
    assert "http-request deny if gwc_path_beg_admin !{ src 192.168.10.0/24 }" in new
    back = hpcfg.find_section(new, "frontend", "fe_s")
    assert back["force_https"] and back["ratelimit"] == "100" and back["binds"][0]["h2"]
    assert [r["action"] for r in back["rules"]] == ["allow_only", "redirect"]
    assert upsert(new, "frontend", copy.deepcopy(back)) == new           # stable after a round trip


@pytest.mark.parametrize("patch,msg", [
    ({"servers": [{"name": "a b", "addr": "1.2.3.4:80"}]}, "server name"),
    ({"servers": [{"name": "a", "addr": "1.2.3.4:80; rm"}]}, "address"),
    ({"timeouts": {"server": "soon"}}, "timeout"),
    ({"balance": "magic"}, "load balancing"),
    ({"servers": [{"name": "a", "addr": "1.2.3.4:80"}, {"name": "a", "addr": "1.2.3.5:80"}]}, "twice"),
    ({"advanced": "global"}, "new section"),
])
def test_validation(patch, msg):
    be = hpcfg.empty_backend()
    be.update(name="be_x", **patch)
    with pytest.raises(hpcfg.CfgError, match=msg):
        hpcfg.apply_ops(CFG, [{"op": "upsert", "kind": "backend", "model": be}])


def test_name_clash_and_helpers():
    be = hpcfg.empty_backend()
    be["name"] = "be_api"
    with pytest.raises(hpcfg.CfgError, match="already exists"):
        hpcfg.apply_ops(CFG, [{"op": "upsert", "kind": "backend", "model": be}])
    assert hpcfg.references(CFG, "be_default") == ["frontend fe_web"]
    assert hpcfg.routed_hosts(CFG)["kodje.adproject.fun"] == "fe_web → be_kodje"
    assert hpcfg.bind_ports(CFG) == {"80": "frontend fe_web"}


@pytest.mark.skipif(not __import__("shutil").which("haproxy"), reason="haproxy not installed")
def test_generated_config_passes_haproxy_check(tmp_path):
    import subprocess
    be = hpcfg.empty_backend()
    be.update(name="be_shop", sticky={"type": "cookie", "cookie": "SRV"}, retries="3", redispatch=True,
              check={"inter": "3s", "rise": "2", "fall": "3"},
              headers=[{"dir": "request", "name": "X-App", "value": "shop"}],
              health={"type": "http", "method": "GET", "path": "/health", "host": "shop.example.com", "expect": "200-399"},
              servers=[{**hpcfg.empty_server(), "name": "s1", "addr": "127.0.0.1:9001", "weight": "50"},
                       {**hpcfg.empty_server(), "name": "s2", "addr": "127.0.0.1:9002", "backup": True, "maxconn": "100"}])
    fe = model(CFG, "frontend", "fe_web")
    fe["ratelimit"] = "50"
    fe["advanced"] = ""            # the fixture routes HTTP to a TCP backend on purpose elsewhere
    fe["rules"] += [{"cond": "host", "value": "shop.example.com www.shop.example.com", "action": "backend", "target": "be_shop"},
                    {"cond": "path_beg", "value": "/admin", "action": "allow_only", "target": "192.168.10.0/24"},
                    {"cond": "header", "hname": "X-Debug", "value": "1", "action": "set_header", "target": "X-Trace: on"},
                    {"cond": "method", "value": "TRACE", "action": "deny"},
                    {"cond": "host", "value": "old.example.com", "action": "redirect", "target": "https://new.example.com/"}]
    tcp = hpcfg.empty_frontend("tcp")
    tcp.update(name="fe_tls", binds=[{"addr": "127.0.0.1:18443"}], default_backend="be_mc",
               rules=[{"cond": "sni", "value": "mc.example.com", "action": "backend", "target": "be_mc"}])
    new = hpcfg.apply_ops(CFG.replace("    stats socket /run/haproxy/admin.sock mode 660 level admin\n", ""),
                          [{"op": "upsert", "kind": "backend", "model": be},
                           {"op": "upsert", "kind": "frontend", "orig_name": "fe_web", "model": fe},
                           {"op": "upsert", "kind": "frontend", "model": tcp}]).replace("bind *:80", "bind 127.0.0.1:18080")
    f = tmp_path / "h.cfg"
    f.write_text(new)
    r = subprocess.run(["haproxy", "-c", "-f", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_blank_lines_elsewhere_are_left_alone():
    text = CFG.replace("backend be_api\n", "\n\n\nbackend be_api\n")
    assert upsert(text, "backend", model(text, "backend", "be_mc")) == text
    be = hpcfg.empty_backend()
    be.update(name="be_z", servers=[{**hpcfg.empty_server(), "name": "z", "addr": "10.0.0.9:80"}])
    new = hpcfg.apply_ops(text, [{"op": "upsert", "kind": "backend", "model": be}])
    assert "\n\n\n\nbackend be_api" in new and new.endswith("    mode tcp\n    server mc 10.0.30.15:25565 check\n\nbackend be_z\n    mode http\n    balance roundrobin\n    option forwardfor\n    server z 10.0.0.9:80 check\n")
