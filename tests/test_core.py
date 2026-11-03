import textwrap

import pytest

from app import __version__
from app.auth import hash_password, verify_password
from app.config import ConfigError, load
from app.configops import diff_stats, sha, unified_diff


def test_version_is_semver():
    parts = __version__.split(".")
    assert len(parts) == 3 and all(p.isdigit() for p in parts)


def test_password_hash_roundtrip():
    h = hash_password("correct horse battery")
    assert h.startswith("scrypt$")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


def test_diff_helpers():
    d = unified_diff("a\nb\n", "a\nc\n", "/etc/x")
    assert diff_stats(d) == {"added": 1, "removed": 1}
    assert sha("x") == sha("x") != sha("y")


def _write(tmp_path, body):
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


def test_load_minimal_config(tmp_path, monkeypatch):
    monkeypatch.setenv("CF_TOKEN_MAIN", "tok")
    s = load(_write(tmp_path, """
        users: {ameer: "scrypt$x"}
        haproxy_nodes: [{name: hp1, host: 10.0.0.1}]
        cloudflared_nodes:
          - name: cf1
            host: 10.0.0.2
            tunnels: [{name: adproject, metrics: "127.0.0.1:20241"}]
        cloudflare:
          accounts: [{name: main, account_id: abc, api_token_env: CF_TOKEN_MAIN}]
    """))
    assert s.haproxy("hp1").config_path == "/etc/haproxy/haproxy.cfg"
    n = s.cfd("cf1")
    assert n.discover and n.tunnel_base_dir == "/root/.cloudflared"
    assert n.tunnels[0].metrics == "127.0.0.1:20241"
    assert s.cf_accounts["main"].api_token == "tok"


@pytest.mark.parametrize("body,msg", [
    ("haproxy_nodes: []\n", "at least one user"),
    ('users: {a: x}\nhaproxy_nodes: [{name: "bad name", host: h}]\n', "invalid name"),
    ('users: {a: x}\ncloudflared_nodes: [{name: c, host: h, tunnels: [{name: t, cf_account: nope}]}]\n', "not defined"),
])
def test_config_errors(tmp_path, body, msg):
    with pytest.raises(ConfigError, match=msg):
        load(_write(tmp_path, body))
