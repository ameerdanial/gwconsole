"""Software versions on the nodes, and updating cloudflared safely.

versions()          cloudflared on each cloudflared node vs the latest Cloudflare release, and
                    HAProxy on each HAProxy node vs what the OS package manager offers (notify only).
update_cloudflared()  package upgrade (apt/dnf) or official binary download (old binary kept), then the
                    node's tunnels are restarted one at a time; if one doesn't come back, cloudflared is
                    put back to the previous version and the tunnels restarted again.
"""
from __future__ import annotations

import asyncio
import os
import re
import shlex
import time

import httpx

from .sshpool import NodeError

RELEASES = os.environ.get("GWC_CFD_RELEASES", "https://api.github.com/repos/cloudflare/cloudflared/releases/latest")
DOWNLOAD = os.environ.get("GWC_CFD_DOWNLOAD", "https://github.com/cloudflare/cloudflared/releases/download/{tag}/cloudflared-linux-{arch}")
_cache: dict = {}


def vparts(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


async def latest_cloudflared() -> dict:
    c = _cache.get("cfd")
    if c and time.time() - c[0] < 6 * 3600:
        return c[1]
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as h:
            r = await h.get(RELEASES, headers={"Accept": "application/vnd.github+json", "User-Agent": "gwconsole"})
            r.raise_for_status()
            tag = str(r.json().get("tag_name", "")).lstrip("v")
        out = {"version": tag, "error": ""}
    except Exception as e:
        out = {"version": "", "error": f"couldn't check github.com: {type(e).__name__}"}
    _cache["cfd"] = (time.time(), out)
    return out


CFD_INFO = r"""B=$(command -v {bin} 2>/dev/null || echo {bin}); V=$("$B" --version 2>/dev/null | head -1)
M=binary; if command -v dpkg >/dev/null && dpkg -S "$(readlink -f "$B")" >/dev/null 2>&1; then M=apt; elif command -v rpm >/dev/null && rpm -qf "$(readlink -f "$B")" >/dev/null 2>&1; then M=dnf; fi
echo "BIN=$(readlink -f "$B")"; echo "VER=$V"; echo "METHOD=$M"; echo "ARCH=$(uname -m)" """

HAP_INFO = r"""V=$({bin} -v 2>/dev/null | head -1); echo "VER=$V"
if command -v apt-cache >/dev/null; then apt-cache policy haproxy 2>/dev/null | sed -n 's/^ *Installed: */INST=/p; s/^ *Candidate: */CAND=/p'
elif command -v dnf >/dev/null; then echo "INST=$(rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' haproxy 2>/dev/null)"; echo "CAND=$(dnf -q --cacheonly repoquery --latest-limit 1 --qf '%{{version}}-%{{release}}' haproxy 2>/dev/null | tail -1)"; fi"""


def _kv(text: str) -> dict:
    return dict(l.split("=", 1) for l in text.splitlines() if "=" in l)


async def node_info(st, n, kind: str) -> dict:
    try:
        if kind == "cloudflared":
            r = await st.pool.run(n, CFD_INFO.format(bin=shlex.quote(n.cloudflared_bin)), timeout=20)
            kv = _kv(r.out)
            m = re.search(r"version (\S+)", kv.get("VER", ""))
            return {"node": n.name, "kind": kind, "installed": m.group(1) if m else "", "method": kv.get("METHOD", ""),
                    "bin": kv.get("BIN", ""), "arch": kv.get("ARCH", "")}
        r = await st.pool.run(n, HAP_INFO.format(bin=shlex.quote(n.haproxy_bin)), timeout=30)
        kv = _kv(r.out)
        m = re.search(r"version (\S+)", kv.get("VER", ""))
        inst, cand = kv.get("INST", "").strip(), kv.get("CAND", "").strip()
        return {"node": n.name, "kind": kind, "installed": m.group(1) if m else inst, "package": inst,
                "candidate": cand if cand and cand != "(none)" else "",
                "update": bool(cand and inst and cand not in ("(none)", inst))}
    except NodeError as e:
        return {"node": n.name, "kind": kind, "error": str(e)}


async def versions(st) -> list[dict]:
    lat = await latest_cloudflared()
    jobs = [node_info(st, n, "cloudflared") for n in st.s.cloudflared_nodes] + \
           [node_info(st, n, "haproxy") for n in st.s.haproxy_nodes]
    out = list(await asyncio.gather(*jobs))
    for x in out:
        if x["kind"] == "cloudflared":
            x["latest"] = lat["version"]
            x["latest_error"] = lat["error"]
            x["update"] = bool(lat["version"] and x.get("installed") and vparts(lat["version"]) > vparts(x["installed"]))
    return out


ARCH = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm", "i686": "386"}


async def update_cloudflared(st, n, log) -> bool:
    """Returns True when every tunnel on the node came back on the new version."""
    info = await node_info(st, n, "cloudflared")
    if info.get("error"):
        raise NodeError(info["error"])
    old, method, binp = info["installed"], info["method"], info["bin"]
    lat = await latest_cloudflared()
    log(f"cloudflared {old} on {n.name} ({'package' if method != 'binary' else 'binary ' + binp}); latest {lat['version'] or '?'}")
    if method == "apt":
        cmd = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade cloudflared"
        back = f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades cloudflared={shlex.quote(old)}"
    elif method == "dnf":
        cmd = "dnf -y -q upgrade cloudflared"
        back = f"dnf -y -q downgrade cloudflared-{shlex.quote(old)}"
    else:
        if not lat["version"]:
            raise NodeError(lat["error"] or "couldn't find the latest version")
        arch = ARCH.get(info["arch"], "")
        if not arch:
            raise NodeError(f"unknown CPU architecture {info['arch']}")
        url = DOWNLOAD.format(tag=lat["version"], arch=arch)
        b = shlex.quote(binp)
        cmd = (f"T=$(mktemp) && (curl -fsSL -o \"$T\" {shlex.quote(url)} || wget -qO \"$T\" {shlex.quote(url)}) && chmod 755 \"$T\" "
               f"&& \"$T\" --version >/dev/null && cp -p {b} {b}.gwc-prev && mv \"$T\" {b}")
        back = f"[ -f {b}.gwc-prev ] && cp -p {b}.gwc-prev {b}"
    r = await st.pool.run(n, cmd, timeout=300, critical=True)
    log(r.text[-1500:] if r.text else "")
    if not r.ok:
        log("✘ the update itself failed — nothing was restarted")
        return False
    new = (await node_info(st, n, "cloudflared")).get("installed", "?")
    if new == old:
        log(f"cloudflared is already the newest version available ({old}) — nothing to restart")
        return True
    log(f"✔ installed {new} (was {old}); restarting tunnels one at a time")
    units = [t.unit for t in await st.inv.tunnels(n, fresh=True)]
    done = []
    for u in units:
        ok = await _restart_and_wait(st, n, u)
        log(f"{'✔' if ok else '✘'} {u} {'back up' if ok else 'did not come back'}")
        done.append(u)
        if not ok:
            log(f"↩ rolling back to {old}")
            rb = await st.pool.run(n, back, timeout=300, critical=True)
            log(rb.text[-800:] if rb.text else "")
            for d in done:
                ok2 = await _restart_and_wait(st, n, d)
                log(f"{'✔' if ok2 else '⚠'} {d} restarted on {old}")
            return False
    return True


async def _restart_and_wait(st, n, unit: str, wait: int = 40) -> bool:
    u = shlex.quote(unit)
    r = await st.pool.run(n, f"systemctl restart {u}", timeout=60, critical=True)
    if not r.ok:
        return False
    end = time.time() + wait
    stable = 0
    while time.time() < end:
        await asyncio.sleep(3)
        a = await st.pool.run(n, f"systemctl is-active {u}", timeout=15)
        stable = stable + 1 if a.out.strip() == "active" else 0
        if stable >= 3:          # active for ~9 s in a row (cloudflared exits quickly on a bad config/credentials)
            return True
    return False
