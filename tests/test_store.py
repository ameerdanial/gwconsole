"""Tests for the database store: users, roles, sessions, settings, encrypted accounts, nodes, import."""
import pytest

from app.config import CloudflaredNode, HAProxyNode, Settings, Tunnel, CFAccount


def test_users_and_last_superadmin_guard(store):
    a = store.create_user("ameer", "Password123", "superadmin", must_change=False)
    b = store.create_user("hafiz", "Password123", "operator")
    assert store.verify("ameer", "Password123")["id"] == a
    assert store.verify("AMEER", "Password123")        # usernames are case-insensitive
    assert not store.verify("ameer", "wrong")
    assert store.user("hafiz")["must_change"] == 1
    with pytest.raises(ValueError, match="last active superadmin"):
        store.set_role(a, "viewer")
    with pytest.raises(ValueError, match="last active superadmin"):
        store.set_disabled(a, True)
    store.set_role(b, "superadmin")
    store.set_role(a, "viewer")                         # fine now: hafiz is superadmin
    with pytest.raises(ValueError):
        store.create_user("hafiz", "Password123", "viewer")
    with pytest.raises(ValueError, match="at least 10"):
        store.create_user("x1", "short", "viewer")
    with pytest.raises(ValueError, match="upper and lower"):
        store.create_user("x2", "alllowercase1", "viewer")


def test_sessions(store):
    uid = store.create_user("ameer", "Password123", "superadmin")
    tok = store.create_session(uid, 1, "10.0.0.1", "pytest")
    u = store.session(tok)
    assert u["username"] == "ameer" and u["role"] == "superadmin" and u["must_change"] is True
    assert store.session("nope") is None
    assert len(store.sessions()) == 1
    store.set_disabled(store.create_user("other", "Password123", "superadmin", must_change=False), False)
    store.set_disabled(uid, True)                        # disabling drops sessions
    assert store.session(tok) is None


def test_settings_validation(store):
    g = store.set_general({"alert_interval": "20", "dashboard_url": "https://gw.lan/"})
    assert g["alert_interval"] == 20 and g["dashboard_url"] == "https://gw.lan"
    with pytest.raises(ValueError):
        store.set_general({"alert_interval": 1})
    with pytest.raises(ValueError):
        store.set_general({"dashboard_url": "javascript:alert(1)"})
    with pytest.raises(ValueError):
        store.set_general({"nope": 1})


def test_cf_accounts_are_encrypted(store):
    store.save_cf_account("main", "0123456789abcdef0123456789abcdef", "tok-secret")
    raw = store.db.one("SELECT token_enc FROM cf_accounts")["token_enc"]
    assert "tok-secret" not in raw and raw.startswith("gAAAA")
    assert store.cf_account("main").api_token == "tok-secret"
    store.save_cf_account("main2", "0123456789abcdef0123456789abcdef", None, old_name="main")   # rename keeps token
    assert store.cf_account("main2").api_token == "tok-secret"
    with pytest.raises(ValueError, match="32-character"):
        store.save_cf_account("bad", "123", "x")


def test_nodes_roundtrip_keeps_tunnel_overrides(store):
    n = CloudflaredNode(name="cf1", host="10.0.0.2", tunnels=[Tunnel(name="adproject", unit="", config_path="", metrics="127.0.0.1:20241")])
    store.save_node("cloudflared", n)
    store.save_node("haproxy", HAProxyNode(name="hp1", host="10.0.0.1", host_key="ssh-ed25519 AAAA"))
    got = {x.name: x for x in store.nodes()}
    assert got["cf1"].tunnels[0].metrics == "127.0.0.1:20241"
    assert got["hp1"].host_key == "ssh-ed25519 AAAA"
    with pytest.raises(ValueError, match="already exists"):
        store.save_node("haproxy", HAProxyNode(name="hp1", host="x"))


def test_import_from_yaml_runs_once(store):
    from app.auth import hash_password
    y = Settings(users={"ameer": hash_password("Password123")},
                 haproxy_nodes=[HAProxyNode(name="hp1", host="10.0.0.1")],
                 cf_accounts={"main": CFAccount("main", "0123456789abcdef0123456789abcdef", "tok")})
    assert store.import_from_yaml(y) == {"users": 1, "nodes": 1, "cf_accounts": 1}
    assert store.import_from_yaml(y) is None
    assert store.user("ameer")["role"] == "superadmin"
    rt = store.runtime(Settings())
    assert [n.name for n in rt.haproxy_nodes] == ["hp1"] and rt.cf_accounts["main"].api_token == "tok"
