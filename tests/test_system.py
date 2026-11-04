"""Tests for v1.3 system features: backups (make, encrypt, restore safety), the root helper's
request parsing and changelog extraction, config history, update/backup APIs, sign-in
security (allowed networks, new-address alerts)."""
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from app import backup, helper, history
from app.store import ip_allowed, normalize_networks

H = {"X-GWC": "1"}


def test_backup_roundtrip_and_encryption(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "config.yaml").write_text("port: 8088\n")
    (etc / "secret.key").write_text("k" * 44)
    import sqlite3
    db = tmp_path / "gw.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (x)")
    con.execute("INSERT INTO t VALUES (42)")
    con.commit()
    con.close()
    (tmp_path / "audit.log").write_text("{}\n")
    out = backup.make(str(etc), str(db), str(tmp_path / "audit.log"), "1.3.0", bak=str(tmp_path / "bak"))
    assert os.path.basename(out).startswith("gwconsole-backup-1.3.0-")
    assert [x["kind"] for x in backup.listing(str(tmp_path / "bak"))] == ["backup"]
    data = Path(out).read_bytes()
    blob = backup.encrypt(data, "correct horse 9")
    assert blob.startswith(backup.MAGIC) and data not in blob
    with pytest.raises(ValueError, match="wrong passphrase"):
        backup.decrypt(blob, "nope nope nope")
    plain = backup.decrypt(blob, "correct horse 9")
    names = backup.restore(plain, root=str(tmp_path / "restored"))
    assert set(names) == {"etc/gwconsole/config.yaml", "etc/gwconsole/secret.key", "var/lib/gwconsole/gwconsole.db",
                          "var/lib/gwconsole/audit.log"}
    con = sqlite3.connect(tmp_path / "restored/var/lib/gwconsole/gwconsole.db")
    assert con.execute("SELECT x FROM t").fetchone() == (42,)
    con.close()
    with pytest.raises(ValueError):
        backup.encrypt(data, "short")


def _tar(entries):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for name, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "link":
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/shadow"
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
            else:
                info.size = 1
            t.addfile(info, io.BytesIO(b"x") if kind == "f" else None)
    return b.getvalue()


@pytest.mark.parametrize("entries", [
    [("etc/gwconsole/secret.key", "f"), ("etc/passwd", "f")],
    [("etc/gwconsole/secret.key", "f"), ("var/lib/gwconsole/../../../root/x", "f")],
    [("etc/gwconsole/secret.key", "f"), ("etc/gwconsole/evil", "link")],
    [("etc/gwconsole/config.yaml", "f")],
    [("etc/gwconsole/secret.key", "f"), ("etc/gwconsole", "f")],
    [("etc/gwconsole/secret.key", "f"), ("etc/gwconsole/sub", "link")],
    [("etc/gwconsole/secret.key", "f"), ("/etc/gwconsole/x", "f")],
    [("etc/gwconsole/secret.key", "f"), ("etc/gwconsole-evil/x", "f")],
    [("etc/gwconsole/secret.key", "f"), ("etc/gwconsole/a/../../../root/x", "f")],
])
def test_restore_refuses_anything_unexpected(entries, tmp_path):
    with pytest.raises(ValueError):
        backup.restore(_tar(entries), root=str(tmp_path))


def test_upgrade_backups_from_install_sh_are_usable(tmp_path):
    """install.sh's own backup (tar of both folders, with sub-folders) verifies and restores the top-level files only."""
    src = tmp_path / "src"
    (src / "etc/gwconsole").mkdir(parents=True)
    (src / "var/lib/gwconsole/config-history/.git").mkdir(parents=True)
    (src / "etc/gwconsole/secret.key").write_bytes(b"k" * 44)
    (src / "etc/gwconsole/config.yaml").write_text("listen: 127.0.0.1\n")
    from app.db import DB
    DB(str(src / "var/lib/gwconsole/gwconsole.db")).close()
    (src / "var/lib/gwconsole/config-history/.git/HEAD").write_text("ref: refs/heads/main\n")
    os.symlink("/etc/shadow", src / "var/lib/gwconsole/config-history/link")
    bak = tmp_path / "gwconsole-1.4.1-20261104-210408.tar.gz"
    with tarfile.open(bak, "w:gz") as t:
        t.add(src / "etc/gwconsole", arcname="etc/gwconsole")
        t.add(src / "var/lib/gwconsole", arcname="var/lib/gwconsole")
    r = backup.verify_file(str(bak), {})
    assert r["ok"] and r["version"] == "1.4.1", r
    (tmp_path / "out/var/lib/gwconsole").mkdir(parents=True)
    (tmp_path / "out/var/lib/gwconsole/gwconsole.db-wal").write_bytes(b"stale")
    names = backup.restore(bak.read_bytes(), root=str(tmp_path / "out"))
    assert sorted(names) == ["etc/gwconsole/config.yaml", "etc/gwconsole/secret.key", "var/lib/gwconsole/gwconsole.db"]
    assert not (tmp_path / "out/var/lib/gwconsole/gwconsole.db-wal").exists()
    assert not (tmp_path / "out/var/lib/gwconsole/config-history").exists()


def test_helper_request_parsing(tmp_path, monkeypatch):
    req = tmp_path / "request"
    monkeypatch.setattr(helper, "REQ", str(req))
    for line, want in [("check by ameer\n", ("check", "", "ameer")), ("upgrade v1.3.1 by ameer", ("upgrade", "v1.3.1", "ameer")),
                       ("backup by ops", ("backup", "", "ops")), ("upgrade v1.3.1; rm -rf / by x", None),
                       ("upgrade main by ameer", None), ("check by a b", None)]:
        req.write_text(line)
        assert helper.read_request() == want
        assert not req.exists()            # always consumed
    os.symlink("/etc/hostname", req)
    assert helper.read_request() is None and not os.path.lexists(req)
    assert helper.vt("v1.10.0") > helper.vt("v1.9.3")


def test_changelog_section():
    text = "# Changelog\n\n## [Unreleased]\n\n## [1.3.1] - 2026-11-05\n### Fixed\n- a\n\n## [1.3.0] - 2026-11-04\n- b\n"
    assert helper.changelog_section(text, "v1.3.1") == "## [1.3.1] - 2026-11-05\n### Fixed\n- a"
    assert helper.changelog_section(text, "v1.3.0") == "## [1.3.0] - 2026-11-04\n- b"
    assert helper.changelog_section(text, "v9.9.9") == ""


def test_config_history(tmp_path):
    repo = str(tmp_path / "hist")
    c1 = history.record_sync(repo, "hp1", "/etc/haproxy/haproxy.cfg", "a\n", "ameer", "changed in the dashboard — note")
    assert c1 and history.record_sync(repo, "hp1", "/etc/haproxy/haproxy.cfg", "a\n", "ameer", "same") is None
    history.record_sync(repo, "hp1", "/etc/haproxy/haproxy.cfg", "a\nb\n", "outside the dashboard", "changed outside the dashboard")
    log = history.log_sync(repo)
    assert [x["author"] for x in log] == ["outside the dashboard", "ameer"]
    assert log[0]["files"] == ["hp1/etc_haproxy_haproxy.cfg"]
    assert "+b" in history.show_sync(repo, log[0]["id"])
    with pytest.raises(ValueError):
        history.show_sync(repo, "HEAD; rm")


def test_networks():
    assert normalize_networks("192.168.10.7/24, 10.0.0.1 10.0.0.1") == "192.168.10.0/24, 10.0.0.1/32"
    with pytest.raises(ValueError):
        normalize_networks("nope")
    assert ip_allowed("8.8.8.8", "")
    assert ip_allowed("192.168.10.9", "192.168.10.0/24") and not ip_allowed("192.168.11.9", "192.168.10.0/24")
    assert ip_allowed("127.0.0.1", "192.168.10.0/24")          # local console always works
    assert ip_allowed("::ffff:192.168.10.9", "192.168.10.0/24")


def test_update_and_backup_apis(client, tmp_path, monkeypatch):
    from app import api_system
    monkeypatch.setattr(api_system, "HELPER_DIR", str(tmp_path / "helper"))
    monkeypatch.setattr(api_system, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(api_system, "BACKUP_DIR", str(tmp_path / "bak"))
    os.makedirs(tmp_path / "state")
    (tmp_path / "state/status.json").write_text(json.dumps({"current": "v1.2.0", "latest": "v1.3.0",
                                                            "available": [{"version": "v1.3.0", "notes": "## [1.3.0]\n- x"}]}))
    client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    d = client.get("/api/system").json()
    assert d["update"]["latest"] == "v1.3.0" and d["source"] in ("git", "tarball")
    assert client.post("/api/system/update/install", json={"version": "v9.9.9"}, headers=H).status_code == 400
    assert client.post("/api/system/update/install", json={"version": "v1.3.0"}, headers=H).json()["ok"]
    assert (tmp_path / "helper/request").read_text() == "upgrade v1.3.0 by root\n"
    assert client.post("/api/system/update/check", headers=H).json()["ok"]
    assert (tmp_path / "helper/request").read_text() == "check by root\n"
    assert client.get("/api/system").json()["pending"]
    # backups: list + passphrase download
    os.makedirs(tmp_path / "bak")
    (tmp_path / "bak/gwconsole-backup-1.3.0-20261104-031700.tar.gz").write_bytes(b"data")
    assert [x["name"] for x in client.get("/api/admin/backups").json()["items"]] == ["gwconsole-backup-1.3.0-20261104-031700.tar.gz"]
    r = client.post("/api/admin/backups/download", json={"name": "gwconsole-backup-1.3.0-20261104-031700.tar.gz", "passphrase": "long enough 1"}, headers=H)
    assert r.status_code == 200 and r.content.startswith(b"GWCBAK1\n")
    assert client.post("/api/admin/backups/download", json={"name": "../../etc/passwd", "passphrase": "long enough 1"}, headers=H).status_code == 404


def test_signin_security(client, monkeypatch):
    from app.state import st
    sent = []

    async def fake(text):
        sent.append(text)
    monkeypatch.setattr(st.engine, "announce", fake)
    assert client.post("/api/login", json={"user": "root", "password": "RootPass1234"}).status_code == 200
    assert sent == []                                     # first ever sign-in: just remembered
    st.store.put("seen_ips:root", ["10.0.0.1"])
    client.cookies.clear()
    client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    client.get("/api/me")                                  # the announcement is a background task
    assert st.store.get("seen_ips:root")[0] == "testclient"
    assert any("New sign-in: root from testclient" in t for t in sent)
    # allowed networks: the test client's address isn't an IP, so it's outside every list
    st.store.put("general", {**st.store.general(), "allowed_networks": "192.168.10.0/24"})
    client.cookies.clear()
    r = client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    assert r.status_code == 403 and "network" in r.json()["error"]
    st.store.put("general", {**st.store.general(), "allowed_networks": ""})
