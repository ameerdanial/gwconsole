"""Tests for adding/removing tunnel hostnames (ingress) and input validation."""
import pytest

from app.tunnelops import edit_ingress, new_config_text, check_hostname, check_service

INDENTED = """tunnel: 6f1c   # adproject tunnel
credentials-file: /root/.cloudflared/adproject/x.json
ingress:
  # main site
  - hostname: www.adproject.fun
    service: http://10.10.10.20:80
  - service: http_status:404
"""

FLUSH = "tunnel: x\ningress:\n- hostname: a.b.com\n  service: http://1.2.3.4:80\n- service: http_status:404\n"


def test_add_inserts_before_catch_all_and_keeps_comments():
    out = edit_ingress(INDENTED, "add", "ERP.adproject.fun", "https://10.0.0.5:443", no_tls_verify=True)
    assert "# adproject tunnel" in out and "# main site" in out
    lines = out.splitlines()
    assert lines.index("  - hostname: erp.adproject.fun") < lines.index("  - service: http_status:404")
    assert "      noTLSVerify: true" in lines


def test_add_then_remove_round_trips_exactly():
    added = edit_ingress(INDENTED, "add", "erp.adproject.fun", "http://10.0.0.5:80")
    assert edit_ingress(added, "remove", "erp.adproject.fun") == INDENTED


def test_flush_style_is_preserved():
    out = edit_ingress(FLUSH, "add", "c.b.com", "tcp://1.2.3.4:25565")
    assert "- hostname: c.b.com\n  service: tcp://1.2.3.4:25565\n- service: http_status:404" in out


def test_catch_all_added_when_missing():
    out = edit_ingress("tunnel: x\n", "add", "c.b.com", "http://x:1")
    assert out.rstrip().endswith("- service: http_status:404")


@pytest.mark.parametrize("args,msg", [
    (("add", "a.b.com", "http://x:1"), "already exists"),
    (("remove", "zz.b.com"), "not found"),
    (("add", "bad host", "http://x"), "invalid hostname"),
    (("add", "ok.b.com", "10.0.0.1:80"), "service must"),
])
def test_rejects_bad_input(args, msg):
    with pytest.raises(ValueError, match=msg):
        edit_ingress(FLUSH, *args)


def test_validators():
    assert check_hostname(" *.Example.com ") == "*.example.com"
    assert check_service("http_status:404") == "http_status:404"
    with pytest.raises(ValueError):
        check_service("http://x; rm -rf /")


def test_new_config_text():
    t = new_config_text("abc", "/root/.cloudflared/n/abc.json", "a.b.com", "http://1.2.3.4:80")
    assert t.startswith("tunnel: abc\ncredentials-file: /root/.cloudflared/n/abc.json")
    assert t.rstrip().endswith("- service: http_status:404")
