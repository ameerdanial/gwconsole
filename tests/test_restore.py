"""Tests for v1.5 restore from the dashboard: what a backup holds (inspect), the nightly-style check that
spots a damaged database, the upload → passphrase → preview → restore flow through the root helper
(password, 2FA code and "RESTORE" required), refusing a backup from a newer version, the helper's request
pattern for restores, and the "newest backup is damaged" alert."""
import io
import json
import os
import tarfile

import pytest

from app import backup, helper, totp
from app.db import DB
from app.store import Store
from app.vault import Vault

H = {"X-GWC": "1"}


def make_backup(tmp_path, version="1.5.0", users=("ameer", "kodje-ops"), damage=False) -> str:
    etc = tmp_path / f"etc-{version}"
    etc.mkdir()
    (etc / "config.yaml").write_text("listen: 127.0.0.1\n")
    Vault(str(etc / "secret.key"), create=True)
    db = tmp_path / f"db-{version}.db"
    s = Store(DB(str(db)), Vault(str(etc / "secret.key")))
    for u in users:
        s.create_user(u, "OpsPass12345", "operator", must_change=False)
    s.db.close()
    (tmp_path / "audit.log").write_text("{}\n")
    out = backup.make(str(etc), str(db), str(tmp_path / "audit.log"), version, bak=str(tmp_path / "bak"))
    if damage:                       # same archive, but the database copy is garbage
        data = backup.open_bytes(out)
        buf = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as src, tarfile.open(fileobj=buf, mode="w:gz") as dst:
            for m in src.getmembers():
                body = src.extractfile(m).read()
                if m.name.endswith("gwconsole.db"):
                    body = b"SQLite format 3\x00" + b"\x00" * 200
                    m.size = len(body)
                dst.addfile(m, io.BytesIO(body))
        with open(out, "wb") as f:
            f.write(buf.getvalue())
    return out


def test_inspect_and_verify(tmp_path):
    p = make_backup(tmp_path)
    info = backup.inspect(backup.open_bytes(p), b"some-other-key")
    assert info["version"] == "1.5.0" and info["users"] == ["ameer", "kodje-ops"] and info["db_ok"] and info["same_key"] is False
    cache = {}
    assert backup.verify_file(p, cache)["ok"] and len(cache) == 1
    bad = make_backup(tmp_path, version="1.4.9", damage=True)
    r = backup.verify_file(bad, cache)
    assert not r["ok"] and r["error"]


def test_helper_restore_requests(tmp_path, monkeypatch):
    req = tmp_path / "request"
    monkeypatch.setattr(helper, "REQ", str(req))
    for line, want in [("restore gwconsole-backup-1.5.0-20261104-030001.tar.gz by ameer",
                        ("restore", "gwconsole-backup-1.5.0-20261104-030001.tar.gz", "ameer")),
                       ("restore upload-0123456789abcdef.tar.gz by ameer", ("restore", "upload-0123456789abcdef.tar.gz", "ameer")),
                       ("restore ../../etc/shadow by ameer", None), ("restore upload-xyz.tar.gz by ameer", None),
                       ("restore gwconsole-a.tar.gz; id by ameer", None), ("upgrade v1.5.0 by ameer", ("upgrade", "v1.5.0", "ameer"))]:
        req.write_text(line)
        assert helper.read_request() == want, line


@pytest.fixture
def bak(client, tmp_path, monkeypatch):
    from app import api_system
    from app.state import st
    monkeypatch.setattr(api_system, "HELPER_DIR", str(tmp_path / "helper"))
    monkeypatch.setattr(api_system, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(api_system, "BACKUP_DIR", str(tmp_path / "bak"))
    os.makedirs(tmp_path / "state", exist_ok=True)
    (tmp_path / "state/status.json").write_text("{}")
    client.post("/api/login", json={"user": "root", "password": "RootPass1234"})
    return st


def test_restore_from_list_needs_password_code_and_confirm(client, tmp_path, bak):
    p = make_backup(tmp_path, version="1.4.1")
    name = os.path.basename(p)
    items = client.get("/api/admin/backups").json()["items"]
    assert items[0]["name"] == name and items[0]["ok"] and items[0]["version"] == "1.4.1"
    pv = client.get(f"/api/admin/backups/{name}/preview").json()
    assert pv["users"] == 2 and pv["lost"]["users"] == ["root"] and pv["db_ok"] and not pv["newer_than_running"]
    body = {"name": name, "password": "RootPass1234", "confirm": "RESTORE"}
    assert client.post("/api/admin/backups/restore", json={**body, "confirm": "yes"}, headers=H).status_code == 400
    assert client.post("/api/admin/backups/restore", json={**body, "password": "wrong"}, headers=H).status_code == 400
    # with two-step sign-in on, the code is needed too
    d = client.post("/api/account/2fa/start", headers=H).json()
    key = d["key"].replace(" ", "")
    client.post("/api/account/2fa/confirm", json={"code": totp.code_at(key, totp.now_step())}, headers=H)
    assert client.post("/api/admin/backups/restore", json={**body, "code": "000000"}, headers=H).status_code == 400
    ok = client.post("/api/admin/backups/restore", json={**body, "code": totp.code_at(key, totp.now_step() + 1)}, headers=H)
    assert ok.status_code == 200
    assert (tmp_path / "helper/request").read_text() == f"restore {name} by root\n"
    acts = [i["action"] for i in client.get("/api/audit?cat=updates").json()["items"]]
    assert "restore requested" in acts
    assert client.get("/api/admin/backups/../../etc/passwd/preview").status_code == 404


def test_upload_encrypted_then_restore_and_refusals(client, tmp_path, bak):
    p = make_backup(tmp_path, version="1.4.0")
    blob = backup.encrypt(backup.open_bytes(p), "correct horse 9")
    up = client.post("/api/admin/backups/upload", content=blob, headers={**H, "Content-Type": "application/octet-stream"}).json()
    assert up["encrypted"] and len(up["upload_id"]) == 16
    assert client.post(f"/api/admin/backups/upload/{up['upload_id']}/open", json={"passphrase": "nope nope"}, headers=H).status_code == 400
    pv = client.post(f"/api/admin/backups/upload/{up['upload_id']}/open", json={"passphrase": "correct horse 9"}, headers=H).json()
    assert pv["name"] == f"upload-{up['upload_id']}.tar.gz" and pv["version"] == "1.4.0"
    spool = os.path.join(os.path.dirname(bak.base.db_path), "restore-spool")
    assert os.listdir(spool) == [pv["name"]]                       # the raw upload was replaced by the checked one
    r = client.post("/api/admin/backups/restore", json={"name": pv["name"], "password": "RootPass1234", "confirm": "RESTORE"}, headers=H)
    assert r.status_code == 200 and (tmp_path / "helper/request").read_text() == f"restore {pv['name']} by root\n"
    # not a backup at all
    junk = client.post("/api/admin/backups/upload", content=b"hello", headers={**H, "Content-Type": "application/octet-stream"}).json()
    assert client.post(f"/api/admin/backups/upload/{junk['upload_id']}/open", json={}, headers=H).status_code == 400
    # made by a newer version than the one running
    newer = make_backup(tmp_path, version="9.0.0")
    pv = client.get(f"/api/admin/backups/{os.path.basename(newer)}/preview").json()
    assert pv["newer_than_running"]
    assert client.post("/api/admin/backups/restore", json={"name": os.path.basename(newer), "password": "RootPass1234",
                                                          "confirm": "RESTORE"}, headers=H).status_code == 400
    assert client.post("/api/admin/backups/upload/zz/open", json={}, headers=H).status_code == 404


def test_damaged_newest_backup_raises_an_alert(client, tmp_path, bak):
    from app import api_system
    make_backup(tmp_path, version="1.5.0", damage=True)
    a = api_system.backup_alerts()
    assert a and a[0]["kind"] == "backup.broken" and "damaged" in a[0]["msg"]
    assert json.dumps(a)
