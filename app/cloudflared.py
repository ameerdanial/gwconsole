"""cloudflared: systemd units, local config.yml ingress, logs, rule testing."""
from __future__ import annotations

import re
import shlex

import yaml

from . import configops
from .config import CloudflaredNode, Settings, Tunnel
from .sshpool import SSHPool

URL_RE = re.compile(r"^(https?|tcp|ssh|rdp)://[A-Za-z0-9.\-*_:/%?=&]+$")
SPLIT = "@@GWC-T@@"
ACTIONS = {"start", "stop", "restart"}


def parse_config(text: str) -> dict:
    try:
        y = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        return {"error": f"YAML error: {e}", "ingress": []}
    if not isinstance(y, dict):
        return {"error": "config is not a YAML mapping", "ingress": []}
    ingress = []
    for rule in y.get("ingress") or []:
        if not isinstance(rule, dict):
            continue
        ingress.append({
            "hostname": rule.get("hostname") or "",
            "path": rule.get("path") or "",
            "service": str(rule.get("service") or ""),
            "origin": rule.get("originRequest") or {},
        })
    return {"error": None, "tunnel": str(y.get("tunnel") or ""),
            "credentials_file": y.get("credentials-file") or "",
            "metrics": y.get("metrics") or "", "protocol": y.get("protocol") or "",
            "ingress": ingress}


def _props(text: str) -> dict:
    p = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            p[k.strip()] = v.strip()

    def i(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    return {"active": p.get("ActiveState", "unknown"), "sub": p.get("SubState", ""),
            "since": p.get("ActiveEnterTimestamp", ""), "restarts": i(p.get("NRestarts")),
            "pid": i(p.get("MainPID")), "enabled": p.get("UnitFileState", "")}


async def status(pool: SSHPool, n: CloudflaredNode, tunnels: list[Tunnel],
                 token_ids: dict | None = None) -> dict:
    token_ids = token_ids or {}
    parts = [f"{shlex.quote(n.cloudflared_bin)} --version 2>&1 | head -1"]
    for t in tunnels:
        parts.append(f"echo {SPLIT}")
        parts.append(f"systemctl show {shlex.quote(t.unit)} -p ActiveState -p SubState "
                     f"-p ActiveEnterTimestamp -p NRestarts -p MainPID -p UnitFileState")
        parts.append("echo @@CFG@@")
        if not t.remote:
            parts.append(f"cat {shlex.quote(t.config_path)} 2>&1")
        parts.append("echo; echo @@READY@@")
        if t.metrics:
            parts.append(f"(curl -fsS -m 2 http://{shlex.quote(t.metrics)}/ready || "
                         f"wget -qO- -T 2 http://{shlex.quote(t.metrics)}/ready) 2>/dev/null")
    r = await pool.run(n, "; ".join(parts))
    chunks = r.out.split(SPLIT)
    out = {"node": n.name, "host": n.host, "site": n.site, "version": chunks[0].strip(), "tunnels": []}
    for t, chunk in zip(tunnels, chunks[1:], strict=False):
        svc_txt, _, rest = chunk.partition("@@CFG@@")
        cfg_txt, _, ready_txt = rest.partition("@@READY@@")
        if t.remote:
            cfg = {"error": None, "tunnel": token_ids.get((n.name, t.name), ""), "ingress": [],
                   "credentials_file": "", "metrics": "", "protocol": ""}
        else:
            cfg = parse_config(cfg_txt)
        ready = None
        m = re.search(r'"readyConnections"\s*:\s*(\d+)', ready_txt)
        if m:
            ready = int(m.group(1))
        out["tunnels"].append({
            "name": t.name, "unit": t.unit, "config_path": t.config_path, "cf_account": t.cf_account,
            "remote": t.remote, "source": t.source,
            "service": _props(svc_txt), "config": cfg, "ready_connections": ready,
        })
    return out


async def service_action(pool: SSHPool, n: CloudflaredNode, t: Tunnel, action: str) -> dict:
    if action not in ACTIONS:
        raise ValueError("action must be start, stop or restart")
    u = shlex.quote(t.unit)
    cmd = f"systemctl {action} {u} 2>&1; rc=$?; sleep 2; systemctl is-active {u}; exit $rc"
    r = await pool.run(n, cmd, timeout=60, critical=True)
    return {"ok": r.ok, "output": r.text}


async def logs(pool: SSHPool, n: CloudflaredNode, t: Tunnel, lines: int) -> str:
    lines = max(10, min(int(lines), 2000))
    r = await pool.run(n, f"journalctl -u {shlex.quote(t.unit)} -n {lines} --no-pager -o short-iso")
    return r.text


async def test_rule(pool: SSHPool, n: CloudflaredNode, t: Tunnel, url: str) -> dict:
    if t.remote:
        raise ValueError("token-run tunnel has no local ingress rules")
    if not URL_RE.match(url):
        raise ValueError("enter a URL like https://app.example.com/path")
    r = await pool.run(n, f"{shlex.quote(n.cloudflared_bin)} tunnel --config {shlex.quote(t.config_path)} "
                          f"ingress rule {shlex.quote(url)} 2>&1")
    return {"ok": r.ok, "output": r.text}


class TunnelConfig:
    kind = "tunnel"

    def __init__(self, pool: SSHPool, s: Settings, n: CloudflaredNode, t: Tunnel):
        if t.remote:
            raise ValueError(f"{t.name} is token-run (remotely managed): edit it in the Cloudflare Zero Trust dashboard")
        self.pool, self.s, self.n, self.t = pool, s, n, t
        self.path = t.config_path
        self.prefix = t.name

    @property
    def label(self):
        return f"Tunnel · {self.t.name} @ {self.n.name}"

    def _vcmd(self):
        return f"{shlex.quote(self.n.cloudflared_bin)} tunnel --config {{file}} ingress validate"

    async def read(self) -> str:
        return await configops.read_file(self.pool, self.n, self.path)

    async def validate(self, content: str) -> dict:
        p = parse_config(content)
        if p["error"]:
            return {"ok": False, "output": p["error"]}
        return await configops.validate(self.pool, self.n, content, self._vcmd())

    async def apply(self, content: str, base_hash: str | None) -> dict:
        p = parse_config(content)
        if p["error"]:
            return {"ok": False, "stage": "validate", "output": p["error"]}
        u = shlex.quote(self.t.unit)
        return await configops.apply(
            self.pool, self.n, cfg_path=self.path, content=content, base_hash=base_hash,
            backup_dir=self.t.backup_dir, prefix=self.prefix, validate_cmd=self._vcmd(),
            activate_cmd=f"systemctl restart {u}", check_cmd=f"systemctl is-active --quiet {u}",
            settle=4, keep=self.s.keep_backups)

    async def backups(self):
        return await configops.list_backups(self.pool, self.n, self.t.backup_dir, self.prefix)

    async def read_backup(self, name: str) -> str:
        return await configops.read_backup(self.pool, self.n, self.t.backup_dir, self.prefix, name)
