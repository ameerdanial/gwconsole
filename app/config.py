"""Load and validate /etc/gwconsole/config.yaml.

Since v1.2.0 config.yaml is the *bootstrap* file: listen address, port and file
paths. Users, nodes and Cloudflare accounts found in it are imported into the
database once (see store.import_from_yaml); after that the web UI is the source
of truth and the dataclasses below are rebuilt from the database.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ConfigError(Exception):
    pass


@dataclass
class SSHTarget:
    name: str
    host: str
    port: int = 22
    user: str = "root"
    sudo: bool = False
    host_key: str = ""   # pinned OpenSSH public key ("ssh-ed25519 AAAA..."); empty = use known_hosts file


@dataclass
class HAProxyNode(SSHTarget):
    config_path: str = "/etc/haproxy/haproxy.cfg"
    stats_socket: str = "/run/haproxy/admin.sock"
    backup_dir: str = "/etc/haproxy/gwc-backups"
    service: str = "haproxy"
    haproxy_bin: str = "haproxy"
    site: str = ""


@dataclass
class Tunnel:
    name: str
    unit: str
    config_path: str
    cf_account: str = ""          # explicit; empty = auto-match by tunnel ID across accounts
    metrics: str = ""             # e.g. 127.0.0.1:20241 (optional)
    backup_dir: str = ""
    remote: bool = False          # token-run (dashboard-managed) tunnel: no local config.yml
    source: str = "config"        # "config" | "discovered"


@dataclass
class CloudflaredNode(SSHTarget):
    cloudflared_bin: str = "cloudflared"
    site: str = ""
    discover: bool = True                  # auto-detect cloudflared*.service units
    tunnel_base_dir: str = "/root/.cloudflared"  # where new tunnels are created
    tunnels: list[Tunnel] = field(default_factory=list)   # explicit entries / overrides


@dataclass
class ServerNode(SSHTarget):
    """Any other Linux host (web, database, cache, game server): health and watched services only."""
    site: str = ""


@dataclass
class CFAccount:
    name: str
    account_id: str
    api_token: str


@dataclass
class Settings:
    listen: str = "0.0.0.0"
    port: int = 8088
    users: dict[str, str] = field(default_factory=dict)
    session_hours: int = 12
    ssh_key_file: str = "/etc/gwconsole/id_ed25519"
    ssh_known_hosts: str | None = "/etc/gwconsole/known_hosts"
    ssh_connect_timeout: int = 8
    audit_log: str = "/var/lib/gwconsole/audit.log"
    db_path: str = "/var/lib/gwconsole/gwconsole.db"
    secret_key_file: str = "/etc/gwconsole/secret.key"
    keep_backups: int = 20
    # general settings (overridden from the database at runtime)
    alert_interval: int = 30
    alert_retention_days: int = 90
    dashboard_url: str = ""
    haproxy_nodes: list[HAProxyNode] = field(default_factory=list)
    cloudflared_nodes: list[CloudflaredNode] = field(default_factory=list)
    server_nodes: list[ServerNode] = field(default_factory=list)
    cf_accounts: dict[str, CFAccount] = field(default_factory=dict)

    # lookups -------------------------------------------------------------
    def haproxy(self, name: str) -> HAProxyNode:
        for n in self.haproxy_nodes:
            if n.name == name:
                return n
        raise KeyError(f"unknown haproxy node {name!r}")

    def cfd(self, name: str) -> CloudflaredNode:
        for n in self.cloudflared_nodes:
            if n.name == name:
                return n
        raise KeyError(f"unknown cloudflared node {name!r}")

    def all_nodes(self) -> list:
        """Every SSH node, whatever its kind (HAProxy, cloudflared, other servers)."""
        return [*self.haproxy_nodes, *self.cloudflared_nodes, *self.server_nodes]

    def node(self, name: str):
        for n in self.all_nodes():
            if n.name == name:
                return n
        raise KeyError(f"unknown node {name!r}")



def _name(v, what):
    if not isinstance(v, str) or not NAME_RE.match(v):
        raise ConfigError(f"{what}: invalid name {v!r} (use letters, digits, _ . -)")
    return v


def _target_kwargs(d: dict, what: str) -> dict:
    if "host" not in d:
        raise ConfigError(f"{what}: 'host' is required")
    return dict(
        name=_name(d.get("name"), what),
        host=str(d["host"]),
        port=int(d.get("port", 22)),
        user=str(d.get("user", "root")),
        sudo=bool(d.get("sudo", False)),
    )


def _secret(d: dict, key: str) -> str:
    """Value may be inline (key) or from an env var (key_env)."""
    env = d.get(f"{key}_env")
    if env:
        return os.environ.get(env, "")
    return str(d.get(key) or "")


def load(path: str | None = None) -> Settings:
    path = path or os.environ.get("GWC_CONFIG", "/etc/gwconsole/config.yaml")
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config not found: {path}")
    raw = yaml.safe_load(p.read_text()) or {}

    s = Settings()
    s.listen = str(raw.get("listen", s.listen))
    s.port = int(raw.get("port", s.port))
    s.users = {str(k): str(v) for k, v in (raw.get("users") or {}).items()}   # imported once into the DB
    s.session_hours = int(raw.get("session_hours", s.session_hours))
    s.audit_log = str(raw.get("audit_log", s.audit_log))
    s.db_path = str(raw.get("db_path", s.db_path))
    s.secret_key_file = str(raw.get("secret_key_file", s.secret_key_file))
    s.keep_backups = int(raw.get("keep_backups", s.keep_backups))

    ssh = raw.get("ssh") or {}
    s.ssh_key_file = str(ssh.get("key_file", s.ssh_key_file))
    kh = ssh.get("known_hosts", s.ssh_known_hosts)
    s.ssh_known_hosts = None if kh in (None, "", "none", False) else str(kh)
    s.ssh_connect_timeout = int(ssh.get("connect_timeout", s.ssh_connect_timeout))

    seen: set[str] = set()
    for i, d in enumerate(raw.get("haproxy_nodes") or []):
        kw = _target_kwargs(d, f"haproxy_nodes[{i}]")
        if kw["name"] in seen:
            raise ConfigError(f"duplicate node name {kw['name']}")
        seen.add(kw["name"])
        s.haproxy_nodes.append(HAProxyNode(
            **kw,
            config_path=str(d.get("config_path", "/etc/haproxy/haproxy.cfg")),
            stats_socket=str(d.get("stats_socket", "/run/haproxy/admin.sock")),
            backup_dir=str(d.get("backup_dir", "/etc/haproxy/gwc-backups")),
            service=str(d.get("service", "haproxy")),
            haproxy_bin=str(d.get("haproxy_bin", "haproxy")),
            site=str(d.get("site", "")),
        ))

    for i, d in enumerate(raw.get("cloudflared_nodes") or []):
        kw = _target_kwargs(d, f"cloudflared_nodes[{i}]")
        if kw["name"] in seen:
            raise ConfigError(f"duplicate node name {kw['name']}")
        seen.add(kw["name"])
        tunnels = []
        for j, t in enumerate(d.get("tunnels") or []):
            what = f"cloudflared_nodes[{i}].tunnels[{j}]"
            tname = _name(t.get("name"), what)
            cfg_path = str(t.get("config_path") or "")
            tunnels.append(Tunnel(
                name=tname,
                unit=str(t.get("unit") or ""),
                config_path=cfg_path,
                cf_account=str(t.get("cf_account", "")),
                metrics=str(t.get("metrics", "")),
                backup_dir=str(t.get("backup_dir") or ""),
            ))
        s.cloudflared_nodes.append(CloudflaredNode(
            **kw,
            cloudflared_bin=str(d.get("cloudflared_bin", "cloudflared")),
            site=str(d.get("site", "")),
            discover=bool(d.get("discover", True)),
            tunnel_base_dir=str(d.get("tunnel_base_dir", "/root/.cloudflared")).rstrip("/"),
            tunnels=tunnels,
        ))

    for i, a in enumerate((raw.get("cloudflare") or {}).get("accounts") or []):
        what = f"cloudflare.accounts[{i}]"
        name = _name(a.get("name"), what)
        if not a.get("account_id"):
            raise ConfigError(f"{what}: 'account_id' is required")
        s.cf_accounts[name] = CFAccount(name=name, account_id=str(a["account_id"]),
                                        api_token=_secret(a, "api_token"))

    for n in s.cloudflared_nodes:
        for t in n.tunnels:
            if t.cf_account and t.cf_account not in s.cf_accounts:
                raise ConfigError(f"tunnel {t.name}: cf_account {t.cf_account!r} not defined under cloudflare.accounts")
    return s
