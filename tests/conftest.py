"""Shared pytest fixtures: a throwaway database + secret key, and a running app with a test config."""
import textwrap

import pytest

from app.db import DB
from app.store import Store
from app.vault import Vault


@pytest.fixture
def store(tmp_path):
    s = Store(DB(str(tmp_path / "t.db")), Vault(str(tmp_path / "secret.key"), create=True))
    yield s
    s.db.close()


@pytest.fixture
def client(tmp_path, monkeypatch):
    """The FastAPI app with an empty node list, a superadmin 'root' and no background checker."""
    from fastapi.testclient import TestClient

    from app.auth import hash_password
    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent(f"""
        listen: 127.0.0.1
        port: 8099
        db_path: {tmp_path}/gw.db
        secret_key_file: {tmp_path}/secret.key
        audit_log: {tmp_path}/audit.log
        users:
          root: "{hash_password('RootPass1234')}"
    """))
    monkeypatch.setenv("GWC_CONFIG", str(cfg))
    from app.main import app
    app.state.no_engine = True
    with TestClient(app) as c:
        from app.state import st
        st.store.set_general({"twofa_required": "nobody"})   # tests that need the 2FA policy set it themselves
        yield c
