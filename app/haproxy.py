"""HAProxy: runtime stats via the admin socket, server state, service, config."""
from __future__ import annotations

import csv
import io
import re
import shlex
import time

from . import configops
from .config import HAProxyNode, Settings
from .sshpool import NodeError, SSHPool

PX_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
SERVER_STATES = {"ready", "drain", "maint"}
SPLIT = "@@GWC-SPLIT@@"


def _sock(n: HAProxyNode, cmd: str) -> str:
    return f"printf '%s\\n' {shlex.quote(cmd)} | socat -t 2 stdio unix-connect:{shlex.quote(n.stats_socket)}"


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_info(text: str) -> dict:
    info = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


def parse_stat(text: str) -> dict:
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines or not lines[0].startswith("# "):
        raise ValueError("unexpected 'show stat' output: " + (lines[0][:200] if lines else "<empty>"))
    lines[0] = lines[0][2:]
    rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
    frontends, backends = [], {}
    order = []
    for r in rows:
        typ = r.get("type")
        base = {
            "name": r["svname"] if typ == "2" else r["pxname"],
            "status": r.get("status", ""),
            "scur": _int(r.get("scur")), "smax": _int(r.get("smax")), "slim": _int(r.get("slim")),
            "stot": _int(r.get("stot")), "req_tot": _int(r.get("req_tot")), "rate": _int(r.get("rate")), "req_rate": _int(r.get("req_rate")),
            "bin": _int(r.get("bin")), "bout": _int(r.get("bout")),
            "ereq": _int(r.get("ereq")), "econ": _int(r.get("econ")), "eresp": _int(r.get("eresp")),
            "hrsp_2xx": _int(r.get("hrsp_2xx")), "hrsp_3xx": _int(r.get("hrsp_3xx")),
            "hrsp_4xx": _int(r.get("hrsp_4xx")), "hrsp_5xx": _int(r.get("hrsp_5xx")),
            "mode": r.get("mode", ""),
        }
        if typ == "0":
            frontends.append(base)
        elif typ == "1":
            be = backends.setdefault(r["pxname"], {"servers": []})
            be.update(base)
            be["act"] = _int(r.get("act"))
            be["bck"] = _int(r.get("bck"))
            be["lastchg"] = _int(r.get("lastchg"))
            if r["pxname"] not in order:
                order.append(r["pxname"])
        elif typ == "2":
            be = backends.setdefault(r["pxname"], {"name": r["pxname"], "servers": []})
            if r["pxname"] not in order:
                order.append(r["pxname"])
            base.update({
                "backend": r["pxname"],
                "addr": r.get("addr", ""),
                "weight": _int(r.get("weight")),
                "backup": r.get("bck") == "1",
                "check_status": r.get("check_status", ""),
                "check_desc": r.get("check_desc", ""),
                "last_chk": r.get("last_chk", ""),
                "check_duration": _int(r.get("check_duration")),
                "lastchg": _int(r.get("lastchg")),
                "downtime": _int(r.get("downtime")),
                "chkfail": _int(r.get("chkfail")),
                "qcur": _int(r.get("qcur")),
                "rtime": _int(r.get("rtime")),
            })
            be["servers"].append(base)
    return {"frontends": frontends, "backends": [backends[k] for k in order]}


def _svc_props(text: str) -> dict:
    p = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            p[k] = v
    return {"active": p.get("ActiveState", "unknown"), "sub": p.get("SubState", ""),
            "since": p.get("ActiveEnterTimestamp", ""), "restarts": _int(p.get("NRestarts")),
            "pid": _int(p.get("MainPID"))}


async def status(pool: SSHPool, n: HAProxyNode) -> dict:
    svc = shlex.quote(n.service)
    cmd = (f"systemctl show {svc} -p ActiveState -p SubState -p ActiveEnterTimestamp -p NRestarts -p MainPID; "
           f"echo {SPLIT}; {_sock(n, 'show info')} 2>&1; echo {SPLIT}; {_sock(n, 'show stat')} 2>&1; echo {SPLIT}; "
           f"d=$(systemctl show {svc} -p ActiveEnterTimestamp --value 2>/dev/null); "
           f"[ -n \"$d\" ] && echo $(( $(date +%s) - $(date -d \"$d\" +%s 2>/dev/null || date +%s) ))")
    r = await pool.run(n, cmd)
    parts = r.out.split(SPLIT)
    if len(parts) < 3:
        raise NodeError(f"{n.name}: unexpected output: {r.text[:300]}")
    out = {"node": n.name, "host": n.host, "site": n.site, "service": _svc_props(parts[0])}
    ago = _int(parts[3].strip()) if len(parts) > 3 else None
    # seconds-ago is measured on the node itself, so clock differences don't matter
    out["service"]["since_epoch"] = int(time.time()) - ago if ago is not None and ago >= 0 else None
    info = parse_info(parts[1])
    out["info"] = {k: info.get(k) for k in (
        "Version", "Uptime", "Uptime_sec", "Process_num", "Nbthread", "CurrConns", "Maxconn",
        "ConnRate", "SessRate", "CumConns", "CumReq", "Run_queue", "Idle_pct", "node", "Release_date")}
    try:
        out.update(parse_stat(parts[2]))
        out["stats_error"] = None
    except ValueError as e:
        out.update({"frontends": [], "backends": []})
        hint = " (is socat installed and 'stats socket ... level admin' set in global?)"
        out["stats_error"] = str(e) + hint
    return out


async def set_server_state(pool: SSHPool, n: HAProxyNode, backend: str, server: str, state: str) -> str:
    if state not in SERVER_STATES or not PX_RE.match(backend) or not PX_RE.match(server):
        raise ValueError("invalid backend/server/state")
    r = await pool.run(n, _sock(n, f"set server {backend}/{server} state {state}"))
    msg = r.text
    if not r.ok or (msg and "No such" in msg) or "Unknown" in msg or "Require" in msg:
        raise NodeError(f"{n.name}: {msg or 'command failed'}")
    return msg or "OK"


def _check_cmd(n: HAProxyNode, file: str) -> str:
    return f"{shlex.quote(n.haproxy_bin)} -c -f {file}"


async def service_action(pool: SSHPool, n: HAProxyNode, action: str) -> dict:
    if action not in ("reload", "restart"):
        raise ValueError("action must be reload or restart")
    svc = shlex.quote(n.service)
    cfg = shlex.quote(n.config_path)
    cmd = (f"{_check_cmd(n, cfg)} 2>&1 || {{ echo '@@GWC:VALIDATE_FAILED'; exit 10; }}; "
           f"systemctl {action} {svc} 2>&1 && sleep 1 && systemctl is-active {svc}")
    r = await pool.run(n, cmd, timeout=60, critical=True)
    return {"ok": r.ok, "output": r.text.replace("@@GWC:VALIDATE_FAILED", "Config check failed — not reloaded.")}


async def logs(pool: SSHPool, n: HAProxyNode, source: str, lines: int) -> str:
    lines = max(10, min(int(lines), 2000))
    if source == "access":
        cmd = (f"if [ -r /var/log/haproxy.log ]; then tail -n {lines} /var/log/haproxy.log; "
               f"else journalctl -u {shlex.quote(n.service)} -n {lines} --no-pager -o short-iso; fi")
    else:
        cmd = f"journalctl -u {shlex.quote(n.service)} -n {lines} --no-pager -o short-iso"
    r = await pool.run(n, cmd)
    return r.text


# ---- config target ---------------------------------------------------------
class HAProxyConfig:
    kind = "haproxy"

    def __init__(self, pool: SSHPool, s: Settings, n: HAProxyNode):
        self.pool, self.s, self.n = pool, s, n
        self.path = n.config_path
        self.prefix = "haproxy.cfg"

    @property
    def label(self):
        return f"HAProxy · {self.n.name}"

    async def read(self) -> str:
        return await configops.read_file(self.pool, self.n, self.path)

    async def validate(self, content: str) -> dict:
        return await configops.validate(self.pool, self.n, content, _check_cmd(self.n, "{file}"))

    async def apply(self, content: str, base_hash: str | None) -> dict:
        svc = shlex.quote(self.n.service)
        return await configops.apply(
            self.pool, self.n, cfg_path=self.path, content=content, base_hash=base_hash,
            backup_dir=self.n.backup_dir, prefix=self.prefix,
            validate_cmd=_check_cmd(self.n, "{file}"),
            activate_cmd=f"systemctl reload {svc}",
            check_cmd=f"systemctl is-active --quiet {svc}",
            settle=1, keep=self.s.keep_backups)

    async def backups(self):
        return await configops.list_backups(self.pool, self.n, self.n.backup_dir, self.prefix)

    async def read_backup(self, name: str) -> str:
        return await configops.read_backup(self.pool, self.n, self.n.backup_dir, self.prefix, name)


# ---- admin stats socket ------------------------------------------------------
_SECTION_RE = re.compile(r"^(global|defaults|frontend|backend|listen|peers|resolvers|userlist|program|"
                         r"http-errors|ring|cache|mailers|log-forward|crt-store|traces)\b")
_SOCK_RE = re.compile(r"^(\s*)stats\s+socket\s+(\S+)(.*)$")


def ensure_admin_socket(text: str, default_path: str) -> tuple[str, str, str]:
    """Make sure the global section has 'stats socket <path> ... level admin'.
    Returns (new_text, socket_path, what) where what is 'ok', 'level' (existing socket raised to
    level admin) or 'added' (new line inserted right after 'global')."""
    lines = text.split("\n")
    g_start = next((i for i, l in enumerate(lines) if re.match(r"^global\b", l)), None)
    if g_start is None:
        raise ValueError("haproxy.cfg has no 'global' section")
    i = g_start + 1
    while i < len(lines) and not _SECTION_RE.match(lines[i]):
        m = _SOCK_RE.match(lines[i])
        if m:
            indent, path, rest = m.groups()
            if re.search(r"\blevel\s+admin\b", rest):
                return text, path, "ok"
            comment = ""
            if "#" in rest:
                rest, comment = rest.split("#", 1)
                comment = "  #" + comment
            rest = re.sub(r"\s+level\s+\S+", "", rest).rstrip()
            if not re.search(r"\bmode\s+\d+", rest):
                rest += " mode 660"
            lines[i] = f"{indent}stats socket {path}{rest} level admin{comment}"
            return "\n".join(lines), path, "level"
        i += 1
    lines.insert(g_start + 1, f"    stats socket {default_path} mode 660 level admin")
    return "\n".join(lines), default_path, "added"
