"""Tests for the alert engine lifecycle (firing → resolved, flapping, unknown scopes, mutes) and notifications."""
import pytest

from app import notify
from app.alerts import FLAP_WINDOW, Engine
from app.config import Settings
from app.state import st


@pytest.fixture
def engine(store):
    st.store, st.s = store, Settings()
    e = Engine()
    yield e


def A(kind, target, sev="warn", node="hp1"):
    return {"key": f"{kind}|{target}", "kind": kind, "sev": sev, "node": node, "where": target, "msg": f"{kind} {target}"}


NONE = {"nodes": set(), "cf": False}


def test_open_then_resolve_after_two_misses(engine):
    a = A("hp.backend_down", "hp1 / be", "crit")
    ch = engine.process([a], NONE, 1000)
    assert [c["event"] for c in ch] == ["opened"]
    assert engine.process([a], NONE, 1030) == []                       # still firing: no repeat
    assert engine.process([], NONE, 1060) == []                        # first miss
    ch = engine.process([], NONE, 1090)
    assert [c["event"] for c in ch] == ["resolved"] and ch[0]["duration"] == 90


def test_escalation_and_flap_reopen(engine):
    a = A("tun.edge_degraded", "cf / t")
    engine.process([a], NONE, 0)
    ch = engine.process([dict(a, sev="crit")], NONE, 30)
    assert [c["event"] for c in ch] == ["escalated"]
    engine.process([], NONE, 60); engine.process([], NONE, 90)       # resolved
    ch = engine.process([a], NONE, 120)                                # back within FLAP_WINDOW
    assert [c["event"] for c in ch] == ["reopened"]
    rows = st.store.db.q("SELECT * FROM alerts")
    assert len(rows) == 1 and rows[0]["flaps"] == 1 and rows[0]["resolved_at"] is None
    engine.process([], NONE, 150); engine.process([], NONE, 180)
    ch = engine.process([a], NONE, 180 + FLAP_WINDOW + 1)              # long after: a new alert
    assert [c["event"] for c in ch] == ["opened"] and len(st.store.db.q("SELECT * FROM alerts")) == 2


def test_unreachable_node_keeps_its_alerts_open(engine):
    a = A("hp.server_down", "hp1 / be/s1")
    engine.process([a], NONE, 0)
    for t in (30, 60, 90):
        engine.process([A("node.unreachable", "hp1", "crit")], {"nodes": {"hp1"}, "cf": False}, t)
    assert st.store.db.one("SELECT resolved_at FROM alerts WHERE kind='hp.server_down'")["resolved_at"] is None


def test_mutes(engine):
    st.store.db.x("INSERT INTO mutes (match, until, created_at) VALUES ('node:hp1', 99999, 0)")
    ch = engine.process([A("hp.backend_down", "hp1 / be")], NONE, 10)
    assert ch[0]["muted"] is True


def test_notify_render_and_filters():
    c = [{"event": "opened", "sev": "crit", "where": "hp1 / be", "msg": "backend <DOWN>", "duration": 0},
         {"event": "resolved", "sev": "warn", "where": "hp1 / be/s1", "msg": "x", "duration": 125}]
    html = notify.render(c, "http://gw", html=True)
    assert "&lt;DOWN&gt;" in html and "after 2m" in html and "http://gw/#/alerts" in html and "1 firing, 1 resolved" in html
    assert notify.wanted(c[0], {"min_severity": "crit"}) and not notify.wanted(c[1], {"min_severity": "crit"})
    assert not notify.wanted(c[1], {"min_severity": "warn", "recoveries": False})
    notify.validate_telegram("123456789:AAH_fake_token_for_testing_abcdefghij", "-1001234567890")
    with pytest.raises(ValueError):
        notify.validate_telegram("nope", "1")
    with pytest.raises(ValueError):
        notify.validate_webhook("https://evil.example/api/webhooks/1/x")
