"""Persistent asyncssh connections, one per node, with auto-reconnect."""
from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass

import asyncssh

from .config import Settings, SSHTarget


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def text(self) -> str:
        return (self.out + ("\n" + self.err if self.err else "")).strip()


class NodeError(Exception):
    pass


class SSHPool:
    def __init__(self, settings: Settings):
        self.s = settings
        self._conns: dict[str, asyncssh.SSHClientConnection] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def _connect(self, t: SSHTarget) -> asyncssh.SSHClientConnection:
        lock = self._locks.setdefault(t.name, asyncio.Lock())
        async with lock:
            c = self._conns.get(t.name)
            if c is not None and not c.is_closed():
                return c
            try:
                c = await asyncio.wait_for(asyncssh.connect(
                    t.host, port=t.port, username=t.user,
                    client_keys=[self.s.ssh_key_file],
                    known_hosts=self._known_hosts(t),
                    keepalive_interval=20,
                ), timeout=self.s.ssh_connect_timeout)
            except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
                raise NodeError(f"{t.name} ({t.host}): SSH connect failed: {e or type(e).__name__}") from e
            self._conns[t.name] = c
            return c

    def _known_hosts(self, t: SSHTarget):
        """Pinned host key from the UI if set, else the known_hosts file."""
        if getattr(t, "host_key", ""):
            pattern = t.host if t.port == 22 else f"[{t.host}]:{t.port}"
            return asyncssh.import_known_hosts(f"{pattern} {t.host_key}\n")
        return self.s.ssh_known_hosts

    async def run(self, t: SSHTarget, cmd: str, *, input: str | None = None, timeout: int = 30,
                  root: bool = True, critical: bool = False) -> Result:
        """Run a shell command. If node.sudo and root=True, wrap with sudo -n sh -c.
        critical=True: the remote script ignores hangups and the call is shielded from
        cancellation, so a closed browser tab can never leave a change half-applied."""
        if critical:
            cmd = "trap '' HUP PIPE INT TERM; " + cmd
            return await asyncio.shield(asyncio.ensure_future(
                self.run(t, cmd, input=input, timeout=timeout, root=root)))
        if root and t.sudo:
            cmd = "sudo -n sh -c " + shlex.quote(cmd)
        for attempt in (1, 2):
            conn = await self._connect(t)
            try:
                r = await asyncio.wait_for(conn.run(cmd, input=input, check=False), timeout=timeout)
                return Result(rc=r.exit_status if r.exit_status is not None else 255,
                              out=str(r.stdout or ""), err=str(r.stderr or ""))
            except (asyncssh.ConnectionLost, asyncssh.DisconnectError, BrokenPipeError, ConnectionResetError):
                self._conns.pop(t.name, None)
                if attempt == 2:
                    raise NodeError(f"{t.name}: SSH connection lost")
            except asyncio.TimeoutError:
                raise NodeError(f"{t.name}: command timed out after {timeout}s")
        raise NodeError(f"{t.name}: unreachable")

    async def put_temp(self, t: SSHTarget, content: str) -> str:
        """Upload content into a private temp file on the node, return its path."""
        r = await self.run(t, 'umask 077; f=$(mktemp /tmp/gwc.XXXXXXXX) && cat > "$f" && echo "$f"',
                           input=content, root=False)
        if not r.ok or not r.out.strip().startswith("/tmp/gwc."):
            raise NodeError(f"{t.name}: could not upload temp file: {r.text}")
        return r.out.strip()

    async def close(self):
        for c in self._conns.values():
            c.close()
        self._conns.clear()


async def scan_host_key(host: str, port: int = 22, timeout: int = 8) -> dict:
    """Fetch a server's SSH host key (no login) so a superadmin can confirm its fingerprint."""
    try:
        key = await asyncio.wait_for(asyncssh.get_server_host_key(
            host, port, server_host_key_algs=["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                                              "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]),
            timeout=timeout)
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
        raise NodeError(f"{host}:{port}: could not read host key: {e or type(e).__name__}") from e
    if key is None:
        raise NodeError(f"{host}:{port}: server sent no host key")
    algo, b64 = key.export_public_key("openssh").decode().split()[:2]
    return {"key": f"{algo} {b64}", "type": algo, "fingerprint": key.get_fingerprint("sha256")}
