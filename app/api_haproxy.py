"""HAProxy Add / Edit APIs: the form model of every frontend and backend, a dry-run plan
(plain-language summary, checks, exact diff, optional haproxy -c), applying a plan through the
safe-apply path, an optional Cloudflare publish step (tunnel ingress + DNS) with undo, and
reachability / free-port probes run on the HAProxy node."""
from __future__ import annotations

import asyncio
import re
import shlex

import httpx
from fastapi import APIRouter, Body, Request

from . import cloudflared, configops, haproxy, history, hpcfg, tunnelops
from .cfapi import CFError
from .collect import resolve_edge, tunnel_ref
from .sshpool import NodeError
from .state import audit, need, shielded, st

router = APIRouter(prefix="/api/haproxy")


def _lock(node: str) -> asyncio.Lock:
    return st.locks.setdefault(node, asyncio.Lock())


def defaults_mode(text: str) -> str:
    lines = text.split("\n")
    for s in hpcfg.sections(lines):
        if s.kind == "defaults":
            for l in lines[s.start + 1:s.end]:
                t = hpcfg._norm(l)
                if len(t) == 2 and t[0] == "mode":
                    return t[1]
    return "tcp"          # HAProxy's own default


async def _tunnels() -> list[dict]:
    out = []
    for n in st.s.cloudflared_nodes:
        try:
            for t in await st.inv.tunnels(n):
                out.append({"node": n.name, "tunnel": t.name, "remote": t.remote})
        except NodeError:
            pass
    return out


def _summary(m: dict) -> str:
    if m["kind"] == "backend":
        n = len(m["servers"])
        b = sum(1 for s in m["servers"] if s.get("backup"))
        return f"{n} server{'s' if n != 1 else ''}" + (f" ({b} backup)" if b else "")
    binds = ", ".join(b["addr"] for b in m["binds"]) or "no bind"
    return f"{binds} · {len(m['rules'])} rule{'s' if len(m['rules']) != 1 else ''}"


@router.get("/{node}/model")
async def model(node: str):
    n = st.s.haproxy(node)
    tg = haproxy.HAProxyConfig(st.pool, st.s, n)
    text = await tg.read()
    d = hpcfg.parse(text)
    for m in d["frontends"] + d["backends"]:
        m["summary"] = _summary(m)
        if m["kind"] == "backend":
            m["used_by"] = [r for r in hpcfg.references(text, m["name"]) if r != f"backend {m['name']}"]
    d.update(hash=configops.sha(text), defaults_mode=defaults_mode(text), host=n.host,
             tunnels=await _tunnels() if st.s.cloudflared_nodes else [])
    return d


def _mode_of(text: str, kind: str, name: str, models: dict) -> str:
    m = models.get((kind, name)) or hpcfg.find_section(text, kind, name)
    return (m or {}).get("mode") or defaults_mode(text)


def _label(kind: str, key: str, line: str) -> str:
    if key.startswith("server:") or line.startswith("server "):
        return "server " + line.split()[1]
    if key.startswith("rule:") and key.endswith(":acl"):
        return ""
    if key.startswith("rule:"):
        return "rule: " + line
    return line.split(" if ")[0]


COND_TXT = {"host": "Host is", "path_beg": "path starts with", "path_end": "path ends with", "path": "path is",
            "path_reg": "path matches", "header": "header", "src": "source IP", "method": "method", "sni": "SNI is"}
ACT_TXT = {"backend": "→", "redirect": "→ redirect to", "redirect_https": "→ redirect to HTTPS", "deny": "→ deny",
           "allow_only": "→ allow only from", "set_header": "→ set header"}


def _rule_text(r: dict) -> str:
    c = COND_TXT.get(r.get("cond"), r.get("cond"))
    if r.get("cond") == "header":
        c = f"header {r.get('hname')} is"
    return f"{c} {r.get('value')} {ACT_TXT.get(r.get('action'), r.get('action'))} {r.get('target') or ''}".strip()


def _plan_text(text: str, new: str, ops: list[dict]) -> list[str]:
    out = []
    for op in ops:
        kind = op["kind"]
        if op["op"] == "delete":
            out.append(f"delete {kind} {op['name']}")
            continue
        m = op["model"]
        if not op.get("orig_name"):
            if kind == "backend":
                out.append(f"new backend {m['name']} — {_summary({**hpcfg.empty_backend(), **m, 'kind': 'backend'})}")
            else:
                out.append(f"new frontend {m['name']} on {', '.join(b['addr'] for b in m.get('binds') or [])} "
                           f"({m.get('mode') or 'default'} mode)")
            continue
        old = hpcfg.find_section(text, kind, op["orig_name"])
        nm = hpcfg.find_section(new, kind, m["name"])
        if not old or not nm:
            continue
        def lines(x):
            return {v for k, v in hpcfg.render(x) if not k.startswith("rule:")}
        ol, nl = lines(old), lines(nm)
        title = f"{kind} {op['orig_name']}" + (f" → renamed {m['name']}" if m["name"] != op["orig_name"] else "")
        ro = [_rule_text(r) for r in old.get("rules", [])]
        rn = [_rule_text(r) for r in nm.get("rules", [])]
        bits = [f"+ {_label(kind, '', l)}" for l in sorted(nl - ol)] + [f"− {_label(kind, '', l)}" for l in sorted(ol - nl)]
        bits += [f"+ rule: {t}" for t in rn if t not in ro] + [f"− rule: {t}" for t in ro if t not in rn]
        if [t for t in rn if t in ro] != [t for t in ro if t in rn]:
            bits.append("rules reordered")
        if (old.get("advanced") or "") != (nm.get("advanced") or ""):
            bits.append("advanced lines changed")
        if bits or m["name"] != op["orig_name"]:
            out.append(f"{title}: " + "; ".join(bits[:8]) + (f"; … {len(bits) - 8} more" if len(bits) > 8 else ""))
    return out


def _checks(text: str, new: str, ops: list[dict]) -> tuple[list[dict], list[str]]:
    checks, errors = [], []
    models = {(op["kind"], op["model"]["name"]): op["model"] for op in ops if op["op"] == "upsert"}
    backends = {m["name"] for m in hpcfg.parse(new)["backends"]}
    lines = new.split("\n")
    backends |= {s.name for s in hpcfg.sections(lines) if s.kind == "listen"}
    old_hosts = hpcfg.routed_hosts(text)
    old_ports = hpcfg.bind_ports(text)
    for op in ops:
        if op["op"] != "upsert":
            continue
        m, kind = op["model"], op["kind"]
        if not op.get("orig_name"):
            checks.append({"ok": True, "text": f"name {m['name']} is free"})
        if kind == "frontend":
            fmode = m.get("mode") or defaults_mode(new)
            targets = [r.get("target") for r in m.get("rules") or [] if r.get("action") == "backend"]
            if m.get("default_backend"):
                targets.append(m["default_backend"])
            for t in targets:
                if t not in backends:
                    errors.append(f"backend {t} doesn't exist")
                elif _mode_of(new, "backend", t, models) != fmode:
                    errors.append(f"{fmode} frontend {m['name']} can't send traffic to {_mode_of(new, 'backend', t, models)} "
                                  f"backend {t} — use the same mode on both")
            orig = hpcfg.find_section(text, "frontend", op.get("orig_name") or "") if op.get("orig_name") else None
            old_vals = {(r["cond"], r["value"]) for r in (orig or {}).get("rules", [])}
            for r in m.get("rules") or []:
                if r.get("cond") == "host" and (r["cond"], r.get("value")) not in old_vals:
                    for h in str(r.get("value") or "").split():
                        if h.lower() in old_hosts:
                            checks.append({"ok": False, "warn": True, "text": f"{h} is already routed ({old_hosts[h.lower()]})"})
                        else:
                            checks.append({"ok": True, "text": f"{h} isn't routed anywhere else"})
            own_old = {b["addr"].rsplit(':', 1)[-1] for b in (orig or {}).get("binds", [])}
            for b in m.get("binds") or []:
                p = str(b.get("addr", "")).rsplit(":", 1)[-1]
                if p in old_ports and p not in own_old:
                    errors.append(f"port {p} is already used by {old_ports[p]}")
        else:
            srv = m.get("servers") or []
            if not srv:
                checks.append({"ok": False, "warn": True, "text": f"backend {m['name']} has no servers yet"})
            elif all(s.get("backup") for s in srv):
                checks.append({"ok": False, "warn": True, "text": f"every server in {m['name']} is a backup — none takes traffic normally"})
    return checks, errors


def _resolve(ops: list[dict]) -> list[dict]:
    """Validate shape; '@be' in a frontend means 'the backend created in this same form'."""
    _ok = isinstance(ops, list) and 0 < len(ops) <= 10
    if not _ok:
        raise ValueError("nothing to do")
    be_name = next((op["model"]["name"] for op in ops if op.get("op") == "upsert" and op.get("kind") == "backend"
                    and isinstance(op.get("model"), dict)), "")
    out = []
    for op in ops:
        op = dict(op)
        if op.get("op") == "upsert":
            mdl = dict(op.get("model") or {})
            if op.get("kind") == "frontend":
                mdl["rules"] = [dict(r, target=be_name) if r.get("target") == "@be" else r for r in mdl.get("rules") or []]
                if mdl.get("default_backend") == "@be":
                    mdl["default_backend"] = be_name
            op["model"] = mdl
        out.append(op)
    return out


async def _cf_check(cf: dict | None) -> dict | None:
    if not cf:
        return None
    nd, tn = str(cf.get("node", "")), str(cf.get("tunnel", ""))
    n, t = await st.inv.get(nd, tn)
    if t.remote:
        raise ValueError(f"tunnel {tn} is token-run: add its hostname in the Cloudflare Zero Trust dashboard instead")
    host = tunnelops.check_hostname(str(cf.get("hostname", "")))
    svc = tunnelops.check_service(str(cf.get("service", "")))
    return {"n": n, "t": t, "hostname": host, "service": svc, "dns": bool(cf.get("dns", True))}


@router.post("/{node}/plan")
async def plan(request: Request, node: str, body: dict = Body(...)):
    need(request, "operator")
    n = st.s.haproxy(node)
    tg = haproxy.HAProxyConfig(st.pool, st.s, n)
    text = await tg.read()
    ops = _resolve(body.get("ops"))
    try:
        new = hpcfg.apply_ops(text, ops)
    except hpcfg.CfgError as e:
        return {"error": str(e), "hash": configops.sha(text)}
    diff = configops.unified_diff(text, new, n.config_path)
    checks, errors = _checks(text, new, ops)
    steps = _plan_text(text, new, ops)
    cf = body.get("cloudflare")
    if cf:
        try:
            c = await _cf_check(cf)
            lt = await tunnelops_has(c)
            if lt:
                errors.append(f"{c['hostname']} is already in tunnel {c['t'].name}")
            steps.append(f"tunnel {c['t'].name}: {c['hostname']} → {c['service']} (tunnel restarts)")
            if c["dns"]:
                steps.append(f"DNS: CNAME {c['hostname']} → tunnel {c['t'].name}")
        except (ValueError, KeyError, NodeError) as e:
            errors.append(f"Cloudflare: {e}")
    out = {"hash": configops.sha(text), "diff": diff, **configops.diff_stats(diff), "plan": steps,
           "checks": checks, "errors": errors}
    if body.get("validate") and not errors and diff:
        out["validation"] = await tg.validate(new)
    return out


async def tunnelops_has(c: dict) -> bool:
    cur = await cloudflared.TunnelConfig(st.pool, st.s, c["n"], c["t"]).read()
    ing = (cloudflared.parse_config(cur).get("ingress") or [])
    return any((r.get("hostname") or "").lower() == c["hostname"] for r in ing)


@router.post("/{node}/apply")
@shielded
async def apply(request: Request, node: str, body: dict = Body(...)):
    need(request, "operator")
    n = st.s.haproxy(node)
    tg = haproxy.HAProxyConfig(st.pool, st.s, n)
    ops = _resolve(body.get("ops"))
    note = str(body.get("note") or "")[:120]
    async with _lock(node):
        text = await tg.read()
        if body.get("base_hash") and configops.sha(text) != body["base_hash"]:
            return {"ok": False, "stage": "conflict", "output": "haproxy.cfg changed on the server meanwhile — review again."}
        new = hpcfg.apply_ops(text, ops)
        _, errors = _checks(text, new, ops)
        if errors:
            return {"ok": False, "stage": "checks", "output": "\n".join("✘ " + e for e in errors)}
        c = await _cf_check(body.get("cloudflare")) if body.get("cloudflare") else None
        steps = []
        history.NOTE.set(note or "; ".join(_plan_text(text, new, ops))[:200])
        r = await tg.apply(new, configops.sha(text))
        head = {"applied": "✔ haproxy.cfg validated, backed up and reloaded",
                "noop": "haproxy.cfg unchanged",
                "validate": "✘ haproxy -c rejected the change — nothing changed",
                "rolled_back": "✘ HAProxy failed to reload — rolled back to the previous config",
                "conflict": "✘ haproxy.cfg changed meanwhile — review again"}.get(r["stage"], r["stage"])
        steps.append(head)
        if not r["ok"] and r["stage"] != "noop":
            if r.get("output"):
                steps += ["", r["output"]]
            out = "\n".join(steps)
            audit(request, "haproxy change", node, False, f"stage={r['stage']} {'; '.join(_plan_text(text, new, ops))}\n{out}")
            return {"ok": False, "stage": r["stage"], "output": out}
        ok = True
        if c:
            ok, cf_steps = await _publish(c)
            steps += cf_steps
            if not ok and r["stage"] == "applied":
                u = await tg.apply(text, configops.sha(new))
                steps.append("↩ haproxy.cfg change undone" if u["ok"] else f"⚠ could not undo haproxy.cfg: {u['output']}")
    out = "\n".join(steps)
    audit(request, "haproxy change", node, ok,
          f"stage={r['stage']} backup={r.get('backup')} {r.get('diff_stats', '')}{' note=' + note if note else ''}\n"
          + "; ".join(_plan_text(text, new, ops)) + "\n" + out)
    st.cf.cache.drop_prefix("tun")
    return {"ok": ok, "stage": r["stage"] if ok else "cloudflare", "output": out, "backup": r.get("backup")}


async def _publish(c: dict) -> tuple[bool, list[str]]:
    """Add the hostname to the tunnel (safe apply + restart), then the DNS record. Undo on failure."""
    from .main import _local_tunnel
    steps = []
    tc = cloudflared.TunnelConfig(st.pool, st.s, c["n"], c["t"])
    async with _lock(c["n"].name):
        cur = await tc.read()
        new = tunnelops.edit_ingress(cur, "add", c["hostname"], service=c["service"])
        r = await tc.apply(new, configops.sha(cur))
        if not r["ok"]:
            steps.append(f"✘ tunnel {c['t'].name}: {r['stage']} — {r.get('output', '')[-400:]}")
            return False, steps
        steps.append(f"✔ tunnel {c['t'].name}: {c['hostname']} → {c['service']} (restarted)")
        if not c["dns"]:
            return True, steps
        try:
            lt = await _local_tunnel(c["n"], c["t"])
            acc, edge = await resolve_edge(c["n"].name, c["t"], tunnel_ref(c["n"].name, lt))
            if not acc or not edge:
                raise CFError("tunnel not found in any configured Cloudflare account")
            steps.append("✔ " + await st.cf.route_dns(acc, edge["id"], c["hostname"]))
            return True, steps
        except (CFError, httpx.HTTPError, NodeError) as e:
            steps.append(f"✘ DNS: {e}")
            cur2 = await tc.read()
            back = tunnelops.edit_ingress(cur2, "remove", c["hostname"])
            u = await tc.apply(back, configops.sha(cur2))
            steps.append(f"↩ {c['hostname']} removed from tunnel {c['t'].name}" if u["ok"] else f"⚠ could not undo the tunnel change: {u['output']}")
            return False, steps


@router.post("/{node}/probe")
async def probe(request: Request, node: str, body: dict = Body(...)):
    """From the HAProxy node: can it reach each server, and is a listen port free?"""
    need(request, "operator")
    n = st.s.haproxy(node)
    addrs = [str(a) for a in (body.get("servers") or [])][:30]
    port = str(body.get("port") or "")
    parts = []
    for a in addrs:
        m = re.fullmatch(r"\[?([A-Za-z0-9_.:\-]+?)\]?:(\d{1,5})", a)
        if not m:
            continue
        h, p = m.groups()
        parts.append(f"if timeout 3 bash -c {shlex.quote(f'</dev/tcp/{h}/{p}')} 2>/dev/null; then echo 'R {a} 1'; else echo 'R {a} 0'; fi")
    if port.isdigit():
        parts.append(f"if command -v ss >/dev/null; then if ss -ltnH 'sport = :{int(port)}' | grep -q .; then echo 'P 1'; else echo 'P 0'; fi; fi")
    if not parts:
        return {"servers": {}, "port_in_use": None}
    r = await st.pool.run(n, "; ".join(parts), timeout=40)
    servers, used = {}, None
    for line in r.out.splitlines():
        t = line.split()
        if t[:1] == ["R"] and len(t) == 3:
            servers[t[1]] = t[2] == "1"
        elif t[:1] == ["P"] and len(t) == 2:
            used = t[1] == "1"
    return {"servers": servers, "port_in_use": used}
