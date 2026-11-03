"""Tests for easier setup: the HAProxy admin-socket fixer, the first-run wizard API, the open
health/script endpoints, "password once" input checks and the CLI's --password-stdin."""
import os
import subprocess
import sys
import textwrap

import pytest

from app.api_admin import _parse_results
from app.haproxy import ensure_admin_socket

H = {"X-GWC": "1"}
CFG = """global
    log /dev/log local0
    user haproxy
{sock}
defaults
    mode http
    stats socket /tmp/not-global.sock level admin

frontend fe
    bind :80
"""


def test_socket_added_after_global_when_missing():
    new, path, what = ensure_admin_socket(CFG.format(sock=""), "/run/haproxy/admin.sock")
    assert what == "added" and path == "/run/haproxy/admin.sock"
    lines = new.split("\n")
    assert lines[0] == "global" and lines[1] == "    stats socket /run/haproxy/admin.sock mode 660 level admin"
    assert new.count("stats socket") == 2          # the one in 'defaults' is not counted as global


def test_existing_socket_raised_to_admin_keeps_path_and_comment():
    cfg = CFG.format(sock="    stats socket /var/lib/haproxy/stats level user  # rhel default")
    new, path, what = ensure_admin_socket(cfg, "/run/haproxy/admin.sock")
    assert what == "level" and path == "/var/lib/haproxy/stats"
    assert "    stats socket /var/lib/haproxy/stats mode 660 level admin  # rhel default" in new
    assert "level user" not in new


def test_existing_admin_socket_unchanged():
    cfg = CFG.format(sock="    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners")
    new, path, what = ensure_admin_socket(cfg, "/x")
    assert (new, path, what) == (cfg, "/run/haproxy/admin.sock", "ok")


def test_no_global_section_is_an_error():
    with pytest.raises(ValueError):
        ensure_admin_socket("frontend fe\n    bind :80\n", "/x")


def test_parse_prepare_results():
    out = "==> x\n@@gwc haproxy=1 cloudflared=0\nnoise\n@@gwc socket=/run/haproxy/admin.sock socket_ok=1\n"
    assert _parse_results(out) == {"haproxy": "1", "cloudflared": "0", "socket": "/run/haproxy/admin.sock", "socket_ok": "1"}


def test_health_and_script_are_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["ok"] is True
    r = client.get("/prepare-node.sh")
    assert r.status_code == 200 and r.text.startswith("#!/usr/bin/env bash") and "authorized_keys" in r.text
    assert client.get("/api/me").status_code == 401        # everything else still needs a login


def test_setup_wizard_flow(client):
    client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    assert client.get("/api/me").json()["setup"] is True               # fresh install, no nodes yet
    d = client.get("/api/admin/setup").json()
    assert d["done"] is False and d["nodes"] == [] and d["notify"] == {"telegram": False, "discord": False}
    r = client.post("/api/admin/setup", json={"done": True, "dashboard_url": "nope"}, headers=H)
    assert r.status_code == 400
    assert client.post("/api/admin/setup", json={"done": True, "dashboard_url": "http://10.0.0.5:8088/"}, headers=H).json()["ok"]
    assert client.get("/api/me").json()["setup"] is False
    assert client.get("/api/admin/general").json()["settings"]["dashboard_url"] == "http://10.0.0.5:8088"
    client.post("/api/admin/setup", json={"done": False}, headers=H)   # "run the wizard again"
    assert client.get("/api/admin/setup").json()["done"] is False


def test_bootstrap_input_checks(client):
    client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    base = {"host": "127.0.0.1", "port": 22, "login": "root", "password": "x",
            "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZvb2JhcmZvb2JhcmZvb2JhcmZvb2Jhcg"}
    r = client.post("/api/admin/nodes/bootstrap", json={**base, "password": ""}, headers=H)
    assert r.status_code == 400 and "password" in r.json()["error"]
    r = client.post("/api/admin/nodes/bootstrap", json={**base, "host_key": ""}, headers=H)
    assert r.status_code == 400 and "host key" in r.json()["error"]
    r = client.post("/api/admin/nodes/bootstrap", json={**base, "login": "bad user"}, headers=H)
    assert r.status_code == 400
    assert "x" not in [v for v in r.json().values()]                   # the password is never echoed


def test_cli_create_admin_from_stdin(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent(f"""
        db_path: {tmp_path}/gw.db
        secret_key_file: {tmp_path}/secret.key
        audit_log: {tmp_path}/audit.log
    """))
    env = {**os.environ, "GWC_CONFIG": str(cfg)}
    run = lambda *a, inp: subprocess.run([sys.executable, "-m", "app", *a], input=inp, env=env,
                                         capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
    r = run("create-admin", "ameer", "--password-stdin", inp="weak\n")
    assert r.returncode != 0 and "at least 10" in r.stderr
    r = run("create-admin", "ameer", "--password-stdin", inp="GoodPass2026\n")
    assert r.returncode == 0 and "superadmin ameer created" in r.stdout
    r = run("create-admin", "ameer", "--password-stdin", inp="GoodPass2026\n")
    assert r.returncode != 0 and "already exists" in r.stderr
    assert "superadmin" in run("users", inp="").stdout
