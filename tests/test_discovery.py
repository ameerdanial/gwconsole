import base64
import json

from app.inventory import parse_discovery

TOKEN = base64.b64encode(json.dumps({"a": "acc", "t": "tid-123", "s": "secret"}).encode()).decode().rstrip("=")

OUT = f"""@@BIN /usr/local/bin/cloudflared
@@U cloudflared-adproject.service
ExecStart={{ path=/usr/local/bin/cloudflared ; argv[]=/usr/local/bin/cloudflared --no-autoupdate --config /root/.cloudflared/adproject/config.yml tunnel run ; ignore_errors=no }}
FragmentPath=/etc/systemd/system/cloudflared-adproject.service
LoadState=loaded
@@U cloudflared@kodje.service
ExecStart={{ path=/usr/local/bin/cloudflared ; argv[]=/usr/local/bin/cloudflared --config=/root/.cloudflared/%i/config.yml tunnel run ; }}
FragmentPath=/etc/systemd/system/cloudflared@.service
LoadState=loaded
@@U cloudflared-penipumy.service
ExecStart={{ path=/usr/local/bin/cloudflared ; argv[]=/usr/local/bin/cloudflared tunnel run --token {TOKEN} ; }}
FragmentPath=/etc/systemd/system/cloudflared-penipumy.service
LoadState=loaded
@@U cloudflared-ghost.service
ExecStart=
FragmentPath=
LoadState=not-found
@@U cloudflared.service
ExecStart={{ path=/usr/bin/cloudflared ; argv[]=/usr/bin/cloudflared --no-autoupdate tunnel run ; }}
FragmentPath=/lib/systemd/system/cloudflared.service
LoadState=loaded
"""


def test_parse_discovery():
    binpath, found = parse_discovery(OUT)
    assert binpath == "/usr/local/bin/cloudflared"
    by = {f["name"]: f for f in found}
    assert set(by) == {"adproject", "kodje", "penipumy", "cloudflared"}
    assert by["adproject"]["config_path"] == "/root/.cloudflared/adproject/config.yml"
    assert by["kodje"]["config_path"] == "/root/.cloudflared/kodje/config.yml"   # %i expanded, --config= form
    assert by["penipumy"]["remote"] and by["penipumy"]["token_tunnel_id"] == "tid-123"
    assert TOKEN not in json.dumps(found)                                       # the token itself is never kept
    assert by["cloudflared"]["config_path"] == ""                               # resolved later via candidates
