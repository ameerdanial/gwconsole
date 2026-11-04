"""Scoped access (v1.5): an operator or viewer can be limited to chosen tunnels, domains and extra HAProxy backends.

What a scope gives is worked out here, from the user's picks plus what the dashboard knows about the gateways:
  * hosts       — hostnames matching their domains, plus every hostname of a tunnel they have
  * tunnels     — tunnels they have get full control; other tunnels only show their in-scope hostnames
  * HAProxy     — a host rule is theirs when all its hostnames are; a backend is theirs when only their
                  hostnames reach it (or it was picked as an extra backend); a backend that their hostnames
                  share with others, or that is a default backend, is visible but locked
Superadmins, and users set to "Everything", get ALL. Every check runs on the server; the UI only hides things.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from fastapi import HTTPException

HOSTISH = re.compile(r"^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class ScopeError(HTTPException):
    def __init__(self, msg: str):
        super().__init__(403, msg)


def norm_host(h: str) -> str:
    return (h or "").strip().lower().rstrip(".")


def domain_matches(pattern: str, host: str) -> bool:
    """`example.com` matches only itself; `*.example.com` matches anything under it (one or more labels)
    but not example.com itself. Whole labels only, case-insensitive, never a substring match."""
    p, h = norm_host(pattern), norm_host(host)
    if not p or not h:
        return False
    if p.startswith("*."):
        return h.endswith("." + p[2:]) and len(h) > len(p) - 1
    return h == p


@dataclass
class Scope:
    all: bool = True
    user: str = ""
    tunnels: set = field(default_factory=set)          # {(node, tunnel)}
    domains: list = field(default_factory=list)        # ["*.kodje.my", "kodje.my"]
    backends: set = field(default_factory=set)         # {(hp_node, backend)} picked explicitly
    tunnel_hosts: set = field(default_factory=set)     # hostnames of the tunnels above

    @property
    def summary(self) -> dict:
        if self.all:
            return {"all": True}
        return {"all": False, "tunnels": sorted(f"{n}/{t}" for n, t in self.tunnels), "domains": list(self.domains),
                "backends": sorted(f"{n}/{b}" for n, b in self.backends)}

    # ------------------------------------------------------------------ hosts and tunnels
    def host_ok(self, host: str) -> bool:
        if self.all:
            return True
        h = norm_host(host)
        return h in self.tunnel_hosts or any(domain_matches(d, h) for d in self.domains)

    def tunnel_ok(self, node: str, tunnel: str) -> bool:
        """Full control of the tunnel (start/stop, config, every hostname on it)."""
        return self.all or (node, tunnel) in self.tunnels

    def tunnel_visible(self, node: str, tunnel: str, hosts) -> bool:
        return self.tunnel_ok(node, tunnel) or any(self.host_ok(h) for h in hosts)

    def need_all(self, what: str):
        if not self.all:
            raise ScopeError(f"{what} isn't part of your access — ask a superadmin")

    def need_host(self, host: str):
        if not self.host_ok(host):
            raise ScopeError(f"{norm_host(host) or 'that hostname'} isn't in your access")

    def need_tunnel(self, node: str, tunnel: str):
        if not self.tunnel_ok(node, tunnel):
            raise ScopeError(f"tunnel {tunnel} on {node} isn't in your access")

    # ------------------------------------------------------------------ HAProxy
    def hp_view(self, node: str, model: dict, routes: list[dict] | None = None) -> HPView:
        return HPView(self, node, model, routes or [])

    # ------------------------------------------------------------------ text targets (alerts, activity)
    def text_ok(self, *texts: str) -> bool:
        """Alerts and activity entries name their target as text (host, node/tunnel, hp:backend/server …)."""
        if self.all:
            return True
        blob = " ".join(t or "" for t in texts).lower()
        words = set(re.findall(r"[a-z0-9][a-z0-9.*_-]*", blob))
        if any(self.host_ok(w) for w in words if "." in w):
            return True
        for n, t in self.tunnels:
            if t.lower() in words and n.lower() in words:
                return True
        for n, b in self.backends | self._own_backends_cache:
            if b.lower() in words:
                return True
        return False

    _own_backends_cache: set = field(default_factory=set)


class HPView:
    """One HAProxy node seen through a scope: which rules and backends are the user's, which are shared."""

    def __init__(self, sc: Scope, node: str, model: dict, routes: list[dict]):
        self.sc, self.node = sc, node
        fes, bes = model.get("frontends") or [], model.get("backends") or []
        names = {b["name"] for b in bes}
        refs: dict[str, set] = {n: set() for n in names}
        for fe in fes:
            for r in fe.get("rules") or []:
                if r.get("action") == "backend" and r.get("target"):
                    hs = str(r.get("value", "")).lower().split() if r.get("cond") in ("host", "sni") else ["*"]
                    refs.setdefault(r["target"], set()).update(hs or ["*"])
            if fe.get("default_backend"):
                refs.setdefault(fe["default_backend"], set()).add("*")
            for w in re.findall(r"[A-Za-z0-9_.:-]+", fe.get("advanced") or ""):
                if w in names:
                    refs[w].add("*")
        self.refs = refs
        if sc.all:
            self.own_backends, self.shared_backends = set(names), set()
            self.own_rules = {fe["name"]: {r.get("_key") for r in fe.get("rules") or []} for fe in fes}
            self.frontends = {fe["name"] for fe in fes}
            return
        own = {b for b in names if (node, b) in sc.backends
               or (refs.get(b) and "*" not in refs[b] and all(sc.host_ok(h) for h in refs[b]))}
        shared = {b for b in names - own if any(h != "*" and sc.host_ok(h) for h in refs.get(b, ()))}
        fe_seen = set()
        for rt in routes:                         # hostnames reaching a backend without a host rule (default backend)
            if rt.get("hp_node") == node and sc.host_ok(rt.get("host", "")):
                if rt.get("backend") and rt["backend"] not in own:
                    shared.add(rt["backend"])
                if rt.get("frontend"):
                    fe_seen.add(rt["frontend"])
        self.own_backends, self.shared_backends = own, shared
        self.own_rules = {}
        for fe in fes:
            keys = {r.get("_key") for r in fe.get("rules") or [] if self.rule_ok(r)}
            if keys:
                self.own_rules[fe["name"]] = keys
        self.frontends = set(self.own_rules) | fe_seen
        sc._own_backends_cache |= {(node, b) for b in own}

    def rule_ok(self, r: dict) -> bool:
        if self.sc.all:
            return True
        if r.get("cond") not in ("host", "sni"):
            return False
        hs = str(r.get("value", "")).lower().split()
        return bool(hs) and all(self.sc.host_ok(h) for h in hs)

    def backend_ok(self, name: str) -> bool:
        return self.sc.all or name in self.own_backends

    def backend_visible(self, name: str) -> bool:
        return self.sc.all or name in self.own_backends or name in self.shared_backends

    # ---- what the user may see -------------------------------------------------------------
    def filter_model(self, model: dict) -> dict:
        """Frontends only with the user's rules (the rest of the frontend is locked), backends they own
        (editable) or share (read-only)."""
        if self.sc.all:
            return model
        fes = []
        for fe in model.get("frontends") or []:
            if fe["name"] not in self.frontends:
                continue
            keys = self.own_rules.get(fe["name"], set())
            fes.append({**fe, "rules": [r for r in fe.get("rules") or [] if r.get("_key") in keys], "advanced": "",
                        "locked": True, "scoped": True,
                        "default_backend": fe.get("default_backend") if self.backend_visible(fe.get("default_backend") or "") else ""})
        bes = [{**b, "locked": b["name"] not in self.own_backends} for b in model.get("backends") or []
               if self.backend_visible(b["name"])]
        return {**model, "frontends": fes, "backends": bes, "scoped": True}

    # ---- what the user may change --------------------------------------------------------
    def rewrite_ops(self, current: dict, ops: list[dict]) -> list[dict]:
        """Scoped users edit only their own host rules and their own backends. The browser only knows those,
        so a frontend upsert is rebuilt here from the live frontend with just the user's rules swapped in."""
        if self.sc.all:
            return ops
        fes = {f["name"]: f for f in current.get("frontends") or []}
        out = []
        for op in ops:
            kind, o = op.get("kind"), dict(op)
            if kind == "frontend":
                if o.get("op") != "upsert" or not o.get("orig_name") or o["orig_name"] not in fes:
                    raise ScopeError("only a superadmin or an unscoped operator can add or delete a frontend")
                cur = fes[o["orig_name"]]
                if (o.get("model") or {}).get("name", cur["name"]) != cur["name"]:
                    raise ScopeError("renaming a frontend isn't part of your access")
                if cur["name"] not in self.frontends:
                    raise ScopeError(f"frontend {cur['name']} isn't in your access")
                mine = self.own_rules.get(cur["name"], set())
                new_rules = []
                for r in (o.get("model") or {}).get("rules") or []:
                    if not self.rule_ok(r):
                        raise ScopeError(f"a rule for {r.get('value') or 'that'} isn't in your access")
                    if r.get("action") == "backend" and r.get("target") and not self.backend_visible(r["target"]) \
                            and r["target"] not in self._new_backends(ops):
                        raise ScopeError(f"backend {r['target']} isn't in your access")
                    new_rules.append(r)
                rules, placed = [], False
                for r in cur.get("rules") or []:
                    if r.get("_key") in mine:
                        if not placed:
                            rules += new_rules
                            placed = True
                    else:
                        rules.append(r)
                if not placed:
                    rules += new_rules
                o["model"] = {**cur, "rules": rules}
                o["model"].pop("orig_name", None)
            elif kind == "backend":
                name = o.get("orig_name") or o.get("name") or (o.get("model") or {}).get("name")
                if o.get("op") == "delete" or o.get("orig_name"):
                    if not self.backend_ok(name):
                        raise ScopeError(f"backend {name} is shared with sites outside your access, or isn't yours")
                    if o.get("orig_name") and (o.get("model") or {}).get("name", name) != name:
                        raise ScopeError("renaming a backend isn't part of your access")
            out.append(o)
        return out

    @staticmethod
    def _new_backends(ops) -> set:
        return {(o.get("model") or {}).get("name") for o in ops
                if o.get("kind") == "backend" and o.get("op") == "upsert" and not o.get("orig_name")}

    def check_change(self, old: dict, new: dict):
        """Safety net under rewrite_ops: compare the parsed config before and after and refuse anything outside
        the scope, whatever ops produced it."""
        if self.sc.all:
            return
        ofe = {f["name"]: f for f in old.get("frontends") or []}
        nfe = {f["name"]: f for f in new.get("frontends") or []}
        if set(ofe) != set(nfe):
            raise ScopeError("adding or removing a frontend isn't part of your access")
        strip = ("rules", "_key", "orig_name", "advanced")
        for name, f in nfe.items():
            o = ofe[name]
            if {k: v for k, v in o.items() if k not in strip} != {k: v for k, v in f.items() if k not in strip}:
                raise ScopeError(f"only your own host rules in {name} can change (its listen addresses, TLS and limits are locked)")
            if _adv(o) != _adv(f):
                raise ScopeError(f"the advanced lines of {name} are locked")
            others_o = [_rule_id(r) for r in o.get("rules") or [] if not self.rule_ok(r)]
            others_n = [_rule_id(r) for r in f.get("rules") or [] if not self.rule_ok(r)]
            if others_o != others_n:
                raise ScopeError(f"rules for hostnames outside your access in {name} can't change")
        obe = {b["name"]: b for b in old.get("backends") or []}
        nbe = {b["name"]: b for b in new.get("backends") or []}
        new_refs = HPView(self.sc, self.node, new, []).refs
        for name in set(obe) | set(nbe):
            a, b = obe.get(name), nbe.get(name)
            if a is not None and b is not None and _same(a, b):
                continue
            if a is None:           # a new backend: only the user's own rules may point at it
                hs = new_refs.get(name, set())
                if "*" in hs or not all(self.sc.host_ok(h) for h in hs):
                    raise ScopeError(f"new backend {name} would be used by sites outside your access")
                continue
            if not self.backend_ok(name):
                raise ScopeError(f"backend {name} is shared with sites outside your access — it's read-only for you")


def _rule_id(r: dict) -> tuple:
    return tuple((k, r.get(k)) for k in ("cond", "value", "hname", "action", "target"))


def _adv(fe: dict) -> list[str]:
    return [line.strip() for line in (fe.get("advanced") or "").splitlines() if line.strip() and not line.strip().startswith("acl gwc_")]


def _same(a: dict, b: dict) -> bool:
    strip = ("_key", "orig_name")
    return {k: v for k, v in a.items() if k not in strip} == {k: v for k, v in b.items() if k not in strip}


# ---------------------------------------------------------------------- loading a user's scope
_cache: dict = {}
_routes: dict = {"at": 0.0, "rows": []}


def routes(db) -> list[dict]:
    """Discovered hostnames and their routes (Monitoring's list, refreshed every 5 minutes), cached for 30 s."""
    if time.time() - _routes["at"] > 30:
        rows = []
        for r in db.q("SELECT host, route FROM checks"):
            try:
                rt = json.loads(r["route"] or "{}")
            except ValueError:
                rt = {}
            rows.append({**rt, "host": r["host"]})
        _routes.update(at=time.time(), rows=rows)
    return _routes["rows"]


def forget():
    _cache.clear()
    _routes["at"] = 0.0


def load(store, u: dict) -> Scope:
    if u.get("role") == "superadmin" or u.get("scope_mode", "all") != "pick":
        return Scope(all=True, user=u.get("username", ""))
    key = (u["id"], u.get("scope_ver", 0))
    rt = routes(store.db)
    hit = _cache.get(key)
    if hit and hit[0] is rt:
        return hit[1]
    items = store.scope_items(u["id"])
    tunnels = {tuple(i["ref"].split("/", 1)) for i in items if i["kind"] == "tunnel" and "/" in i["ref"]}
    sc = Scope(all=False, user=u.get("username", ""), tunnels=tunnels,
               domains=[i["ref"] for i in items if i["kind"] == "domain"],
               backends={tuple(i["ref"].split("/", 1)) for i in items if i["kind"] == "backend" and "/" in i["ref"]})
    for r in rt:
        t = r.get("tunnel") or {}
        if (t.get("node"), t.get("name")) in tunnels:
            sc.tunnel_hosts.add(norm_host(r["host"]))
    _cache[key] = (rt, sc)
    return sc
