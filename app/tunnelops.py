"""Tunnel lifecycle on the cloudflared node: create, delete (archive), and
comment-preserving ingress edits."""
from __future__ import annotations

import io
import json
import posixpath
import re
import shlex
import time

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.util import load_yaml_guess_indent

from .config import CloudflaredNode, Tunnel
from .sshpool import NodeError, SSHPool

TUNNEL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$")
HOST_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SERVICE_RE = re.compile(r"^((https?|tcp|ssh|rdp|smb|unix|unix\+tls)://[A-Za-z0-9.\-_:/\[\]%@]+|http_status:\d{3}|hello_world|bastion)$")
PATH_RE = re.compile(r"^[\x21-\x7e]{1,200}$")


def check_hostname(h: str) -> str:
    h = (h or "").strip().lower()
    if not HOST_RE.match(h):
        raise ValueError(f"invalid hostname {h!r}")
    return h


def check_service(svc: str) -> str:
    svc = (svc or "").strip()
    if not SERVICE_RE.match(svc):
        raise ValueError("service must look like http://10.0.0.5:80, https://host:443, tcp://10.0.0.5:25565, "
                         "ssh://host:22 or http_status:404")
    return svc


# ---------------------------------------------------------------- ingress edit
def _yaml(text: str):
    # keep the file's own style: "ingress:\n  - hostname:" (seq 4 / offset 2) or "- hostname:" (seq 2 / offset 0)
    _, ind, bsi = load_yaml_guess_indent(text) if text.strip() else (None, 2, 0)
    ind, bsi = ind or 2, bsi or 0
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=(ind - bsi) if ind - bsi >= 2 else 2, sequence=ind, offset=bsi)
    return y


def edit_ingress(text: str, action: str, hostname: str, service: str = "", path: str = "",
                 no_tls_verify: bool = False, http_host_header: str = "") -> str:
    y = _yaml(text)
    doc = y.load(text) or CommentedMap()
    if not isinstance(doc, dict):
        raise ValueError("config.yml is not a YAML mapping")
    ingress = doc.get("ingress")
    if ingress is None:
        doc["ingress"] = ingress = []
    hostname = check_hostname(hostname)
    path = (path or "").strip()
    if path and not PATH_RE.match(path):
        raise ValueError("invalid path (no spaces, max 200 chars)")

    def same(r):
        return isinstance(r, dict) and str(r.get("hostname") or "").lower() == hostname \
            and str(r.get("path") or "") == path

    if action == "add":
        service = check_service(service)
        if any(same(r) for r in ingress):
            raise ValueError(f"{hostname}{' ' + path if path else ''} already exists in this tunnel")
        rule = CommentedMap()
        rule["hostname"] = hostname
        if path:
            rule["path"] = path
        rule["service"] = service
        origin = CommentedMap()
        if no_tls_verify:
            origin["noTLSVerify"] = True
        if http_host_header:
            h = check_hostname(http_host_header)
            origin["httpHostHeader"] = h
        if origin:
            rule["originRequest"] = origin
        has_catch_all = bool(ingress) and isinstance(ingress[-1], dict) and not ingress[-1].get("hostname") \
            and not ingress[-1].get("path")
        if has_catch_all:
            ingress.insert(len(ingress) - 1, rule)
        else:
            ingress.append(rule)
            ingress.append(CommentedMap([("service", "http_status:404")]))
    elif action == "remove":
        idx = [i for i, r in enumerate(ingress) if same(r)]
        if not idx:
            raise ValueError(f"{hostname} not found in this tunnel's ingress")
        for i in reversed(idx):
            del ingress[i]
    else:
        raise ValueError("action must be add or remove")
    buf = io.StringIO()
    y.dump(doc, buf)
    return buf.getvalue()


def new_config_text(tunnel_id: str, creds_path: str, hostname: str = "", service: str = "") -> str:
    lines = [f"tunnel: {tunnel_id}", f"credentials-file: {creds_path}", "", "ingress:"]
    if hostname:
        lines += [f"  - hostname: {hostname}", f"    service: {service}"]
    lines += ["  - service: http_status:404", ""]
    return "\n".join(lines)


def unit_text(name: str, binpath: str, cfg_path: str) -> str:
    return f"""[Unit]
Description=Cloudflare Tunnel ({name}) - managed by gwconsole
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart={binpath} --no-autoupdate --config {cfg_path} tunnel run
Restart=on-failure
RestartSec=5s
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------- create
async def preflight_create(pool: SSHPool, n: CloudflaredNode, name: str, binpath: str) -> dict:
    d = f"{n.tunnel_base_dir}/{name}"
    unit_path = f"/etc/systemd/system/cloudflared-{name}.service"
    r = await pool.run(n, f"test -e {shlex.quote(d)} && echo HAS_DIR; test -e {shlex.quote(unit_path)} && echo HAS_UNIT; "
                          f"command -v {shlex.quote(binpath)} || echo NO_BIN")
    if "NO_BIN" in r.out:
        raise ValueError(f"cloudflared binary not found on {n.name} ({binpath})")
    if "HAS_DIR" in r.out:
        raise ValueError(f"{d} already exists on {n.name}")
    if "HAS_UNIT" in r.out:
        raise ValueError(f"{unit_path} already exists on {n.name}")
    resolved = [l for l in r.out.splitlines() if l.startswith("/")]
    return {"dir": d, "unit_path": unit_path, "bin": resolved[0] if resolved else binpath}


async def install_tunnel(pool: SSHPool, n: CloudflaredNode, name: str, pre: dict, account_tag: str,
                         tunnel_id: str, secret: str, hostname: str, service: str) -> dict:
    """Write creds + config + unit, validate, enable --now, verify. Cleans up after itself on failure."""
    d, unit_path, binpath = pre["dir"], pre["unit_path"], pre["bin"]
    cfg = f"{d}/config.yml"
    creds_path = f"{d}/{tunnel_id}.json"
    unit = f"cloudflared-{name}.service"
    creds = json.dumps({"AccountTag": account_tag, "TunnelSecret": secret, "TunnelID": tunnel_id})
    t_creds = await pool.put_temp(n, creds)
    t_cfg = await pool.put_temp(n, new_config_text(tunnel_id, creds_path, hostname, service))
    t_unit = await pool.put_temp(n, unit_text(name, binpath, cfg))
    Q = shlex.quote
    script = f"""
D={Q(d)}; CFG={Q(cfg)}; CREDS={Q(creds_path)}; UNITP={Q(unit_path)}; UNIT={Q(unit)}
fail() {{ echo "@@GWC:FAIL $1"; systemctl disable --now "$UNIT" >/dev/null 2>&1; rm -f "$UNITP"; systemctl daemon-reload;
         rm -rf "$D"; rm -f {Q(t_creds)} {Q(t_cfg)} {Q(t_unit)}; exit 1; }}
mkdir -p "$D" && chmod 700 "$D" || fail mkdir
install -m 600 {Q(t_creds)} "$CREDS" || fail creds
install -m 644 {Q(t_cfg)} "$CFG" || fail config
{Q(binpath)} tunnel --config "$CFG" ingress validate 2>&1 || fail validate
install -m 644 {Q(t_unit)} "$UNITP" || fail unit
rm -f {Q(t_creds)} {Q(t_cfg)} {Q(t_unit)}
systemctl daemon-reload || fail daemon-reload
systemctl enable --now "$UNIT" 2>&1 || {{ journalctl -u "$UNIT" -n 25 --no-pager 2>&1; fail start; }}
sleep 4
systemctl is-active --quiet "$UNIT" || {{ journalctl -u "$UNIT" -n 25 --no-pager 2>&1; fail not-active; }}
echo "@@GWC:OK"
"""
    r = await pool.run(n, script, timeout=90, critical=True)
    out = r.out + r.err
    clean = "\n".join(l for l in out.splitlines() if not l.startswith("@@GWC:")).strip()
    m = re.search(r"@@GWC:FAIL (\S+)", out)
    return {"ok": "@@GWC:OK" in out, "stage": m.group(1) if m else ("ok" if "@@GWC:OK" in out else "unknown"),
            "output": clean, "config_path": cfg, "unit": unit}


# ---------------------------------------------------------------- delete
async def remove_local(pool: SSHPool, n: CloudflaredNode, t: Tunnel, creds_file: str, fragment: str) -> dict:
    """Stop + disable the unit and move its files to <base>/.gwc-archive/<name>-<ts>/ (nothing is rm'ed)."""
    Q = shlex.quote
    archive = f"{n.tunnel_base_dir}/.gwc-archive/{t.name}-{time.strftime('%Y%m%d-%H%M%S')}"
    moves = []
    if t.config_path:
        moves.append(t.config_path)
        if t.backup_dir:
            moves.append(t.backup_dir)
    if creds_file:
        moves.append(creds_file)
    # only archive unit files we can safely own: /etc/systemd/system/cloudflared-<name>.service (not templates/packages)
    own_unit = (fragment.startswith("/etc/systemd/system/") and "@" not in t.unit
                and posixpath.basename(fragment) == t.unit)
    if own_unit:
        moves.append(fragment)
    mv = "\n".join(f'[ -e {Q(m)} ] && mv -n {Q(m)} "$A/" && echo "archived {m}"' for m in moves)
    cfg_dir = posixpath.dirname(t.config_path) if t.config_path else ""
    script = f"""
A={Q(archive)}; UNIT={Q(t.unit)}
systemctl disable --now "$UNIT" 2>&1; echo "stopped + disabled $UNIT"
mkdir -p "$A" && chmod 700 "$A"
{mv}
{"systemctl daemon-reload" if own_unit else "true"}
{f'[ "$(ls -A {Q(cfg_dir)} 2>/dev/null)" ] || rmdir {Q(cfg_dir)} 2>/dev/null' if cfg_dir and cfg_dir not in ("/etc/cloudflared", "/root/.cloudflared", n.tunnel_base_dir) else "true"}
echo "@@GWC:OK archive=$A"
"""
    r = await pool.run(n, script, timeout=60, critical=True)
    out = (r.out + r.err)
    if "@@GWC:OK" not in out:
        raise NodeError(f"{n.name}: removing {t.name} failed: {out.strip()[-500:]}")
    return {"archive": archive, "output": "\n".join(l for l in out.splitlines() if not l.startswith("@@GWC:")).strip()}
