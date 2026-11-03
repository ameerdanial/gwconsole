"""Tunnel inventory: auto-discover cloudflared systemd units on each node,
merged with optional explicit entries from config.yaml."""
from __future__ import annotations

import base64
import json
import posixpath
import re
import shlex
import time
from dataclasses import replace

from .config import NAME_RE, CloudflaredNode, Settings, Tunnel
from .sshpool import SSHPool

CONFIG_RE = re.compile(r"--config(?:=|\s+)(\S+)")
TOKEN_RE = re.compile(r"--token(?:=|\s+)(\S+)")
TTL = 30


def _unit_name(unit: str) -> str | None:
    base = unit.removesuffix(".service")
    if base == "cloudflared":
        return "cloudflared"
    if base.startswith("cloudflared@"):
        return base.split("@", 1)[1] or None
    if base.startswith("cloudflared-"):
        return base[len("cloudflared-"):] or None
    return None


def _token_tunnel_id(token: str) -> str:
    """A tunnel token is base64 JSON {"a": account, "t": tunnel_id, "s": secret}. Keep only the ID."""
    try:
        pad = "=" * (-len(token) % 4)
        return str(json.loads(base64.b64decode(token + pad)).get("t") or "")
    except Exception:
        return ""


def parse_discovery(out: str) -> tuple[str, list[dict]]:
    binpath, units, cur = "", [], None
    for line in out.splitlines():
        if line.startswith("@@BIN "):
            binpath = line[6:].strip()
        elif line.startswith("@@U "):
            cur = {"unit": line[4:].strip(), "props": {}}
            units.append(cur)
        elif cur is not None and "=" in line:
            k, v = line.split("=", 1)
            cur["props"][k] = v
    found = []
    for u in units:
        name = _unit_name(u["unit"])
        p = u["props"]
        if not name or not NAME_RE.match(name) or p.get("LoadState") == "not-found":
            continue
        exec_start = p.get("ExecStart", "")
        m = re.search(r"argv\[\]=([^;]*)", exec_start)
        argv = (m.group(1) if m else exec_start).strip()
        inst = u["unit"].split("@", 1)[1].removesuffix(".service") if "@" in u["unit"] else ""
        argv = argv.replace("%i", inst).replace("%I", inst)
        tok = TOKEN_RE.search(argv)
        cfg = CONFIG_RE.search(argv)
        found.append({
            "name": name, "unit": u["unit"],
            "config_path": cfg.group(1).strip("'\"") if cfg else "",
            "remote": bool(tok),
            "token_tunnel_id": _token_tunnel_id(tok.group(1)) if tok else "",
            "fragment": p.get("FragmentPath", ""),
        })
    return binpath, found


class Inventory:
    def __init__(self, s: Settings, pool: SSHPool):
        self.s, self.pool = s, pool
        self._cache: dict[str, tuple[float, list[Tunnel]]] = {}
        self.bins: dict[str, str] = {}
        self.token_ids: dict[tuple[str, str], str] = {}   # (node, tunnel) -> tunnel id for token-run tunnels
        self.fragments: dict[tuple[str, str], str] = {}

    def invalidate(self, node: str | None = None):
        if node:
            self._cache.pop(node, None)
        else:
            self._cache.clear()

    async def tunnels(self, n: CloudflaredNode, fresh: bool = False) -> list[Tunnel]:
        c = self._cache.get(n.name)
        if c and not fresh and time.time() - c[0] < TTL:
            return c[1]
        discovered: list[dict] = []
        if n.discover:
            bin_q = shlex.quote(n.cloudflared_bin)
            script = (
                f'echo "@@BIN $(command -v {bin_q} 2>/dev/null || echo {bin_q})"; '
                "{ systemctl list-unit-files --type=service --no-legend --no-pager 'cloudflared*' 2>/dev/null | awk '{print $1}'; "
                "  systemctl list-units --type=service --all --no-legend --no-pager --plain 'cloudflared*' 2>/dev/null | awk '{print $1}'; } "
                "| sort -u | while read -r u; do case \"$u\" in *@.service|'') continue;; esac; "
                'echo "@@U $u"; systemctl show "$u" -p ExecStart -p FragmentPath -p LoadState --no-pager; done'
            )
            r = await self.pool.run(n, script)
            binpath, discovered = parse_discovery(r.out)
            self.bins[n.name] = binpath or n.cloudflared_bin
            # find config files for units started without --config
            missing = [d for d in discovered if not d["config_path"] and not d["remote"]]
            if missing:
                checks = []
                for d in missing:
                    cands = [f"{n.tunnel_base_dir}/{d['name']}/config.yml", f"{n.tunnel_base_dir}/{d['name']}/config.yaml",
                             "/root/.cloudflared/config.yml", "/etc/cloudflared/config.yml"]
                    checks.append("; ".join(f"test -f {shlex.quote(c)} && {{ echo {shlex.quote(d['name'])}={shlex.quote(c)}; }}" for c in cands)
                                  + " ; true")
                r2 = await self.pool.run(n, " ; ".join(checks))
                hit: dict[str, str] = {}
                for line in r2.out.splitlines():
                    k, _, v = line.partition("=")
                    hit.setdefault(k, v)
                for d in missing:
                    d["config_path"] = hit.get(d["name"], "")
        else:
            self.bins[n.name] = n.cloudflared_bin

        by_name: dict[str, Tunnel] = {}
        for d in discovered:
            if not d["config_path"] and not d["remote"]:
                continue  # can't manage it without a config file
            by_name[d["name"]] = Tunnel(name=d["name"], unit=d["unit"], config_path=d["config_path"],
                                        remote=d["remote"], source="discovered")
            if d["token_tunnel_id"]:
                self.token_ids[(n.name, d["name"])] = d["token_tunnel_id"]
            self.fragments[(n.name, d["name"])] = d["fragment"]
        for e in n.tunnels:  # explicit entries override / add
            t = by_name.get(e.name)
            if t:
                by_name[e.name] = replace(
                    t, unit=e.unit or t.unit, config_path=e.config_path or t.config_path,
                    cf_account=e.cf_account, metrics=e.metrics, backup_dir=e.backup_dir, source="config")
            elif e.config_path:
                by_name[e.name] = replace(e, unit=e.unit or f"cloudflared-{e.name}.service")
        out = []
        for t in sorted(by_name.values(), key=lambda x: x.name):
            if not t.backup_dir and t.config_path:
                t = replace(t, backup_dir=posixpath.dirname(t.config_path) + "/gwc-backups")
            out.append(t)
        self._cache[n.name] = (time.time(), out)
        return out

    async def get(self, node: str, tunnel: str) -> tuple[CloudflaredNode, Tunnel]:
        n = self.s.cfd(node)
        for fresh in (False, True):
            for t in await self.tunnels(n, fresh=fresh):
                if t.name == tunnel:
                    return n, t
        raise KeyError(f"unknown tunnel {tunnel!r} on {node!r}")
