"""HAProxy config model for the Add / Edit forms.

parse()         haproxy.cfg text → sections; each frontend/backend becomes a form model:
                known directives as fields, everything else kept verbatim in `advanced`.
apply_ops()     a list of upsert/delete operations → new haproxy.cfg text. Edits are merged
                line by line: unchanged lines keep their exact formatting and position, changed
                lines are rewritten in place, new lines go next to their kind, and lines the form
                doesn't manage are never touched.
references()    which frontends use a backend (delete protection).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SECTION_KW = {"global", "defaults", "frontend", "backend", "listen", "peers", "resolvers", "userlist",
              "program", "http-errors", "ring", "cache", "mailers", "log-forward", "crt-store", "traces",
              "acme", "fcgi-app"}
NAME_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
TIME_RE = re.compile(r"^\d+(us|ms|s|m|h|d)?$")
HOST_RE = re.compile(r"^(\*\.)?[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
ADDR_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.\-]+|\*)?:\d{1,5}(-\d{1,5})?$")
SERVER_ADDR_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.\-]+)(:\d{1,5})?$")
HDR_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~\-]{1,64}$")
CIDR_RE = re.compile(r"^[0-9A-Fa-f:.]+(/\d{1,3})?(,[0-9A-Fa-f:.]+(/\d{1,3})?)*$")
SAFE_RE = re.compile(r"^[^\s#{}\"'\\]{1,500}$")
BALANCE = ["roundrobin", "static-rr", "leastconn", "first", "source", "uri", "url_param", "hdr(host)", "random"]
CONDS = {"host", "path_beg", "path_end", "path", "path_reg", "header", "src", "method", "sni"}
ACTIONS = {"backend", "redirect", "redirect_https", "deny", "allow_only", "set_header"}
IND = "    "


class CfgError(ValueError):
    pass


# ---------------------------------------------------------------- parsing helpers
def _strip_comment(line: str) -> tuple[str, str]:
    """Split 'directive  # comment' (a # outside quotes after whitespace)."""
    q = None
    for i, ch in enumerate(line):
        if ch in "\"'" and (q is None or q == ch):
            q = None if q else ch
        elif ch == "#" and q is None and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip(), line[i:]
    return line.rstrip(), ""


def _norm(s: str) -> list[str]:
    return _strip_comment(s)[0].split()


@dataclass
class Section:
    kind: str
    name: str
    start: int            # header line index
    end: int              # exclusive: first line after the section body
    header_rest: str = ""  # anything after the name on the header line (bind address of a listen, comment)


def sections(lines: list[str]) -> list[Section]:
    heads = []
    for i, l in enumerate(lines):
        toks = _norm(l)
        if toks and toks[0] in SECTION_KW and not l[:1].isspace():
            heads.append((i, toks))
    out = []
    for k, (i, toks) in enumerate(heads):
        end = heads[k + 1][0] if k + 1 < len(heads) else len(lines)
        # trailing blank lines and column-0 comments belong to whatever follows
        while end - 1 > i and (not lines[end - 1].strip() or lines[end - 1].startswith("#")):
            end -= 1
        name = toks[1] if len(toks) > 1 else ""
        raw = _strip_comment(lines[i])
        rest = raw[0].split(None, 2)[2] if len(raw[0].split(None, 2)) > 2 else ""
        out.append(Section(toks[0], name, i, end, (" " + rest if rest else "") + ("  " + raw[1] if raw[1] else "")))
    return out


# ---------------------------------------------------------------- models
def empty_backend(mode="http") -> dict:
    return {"kind": "backend", "name": "", "mode": mode, "balance": "roundrobin",
            "sticky": {"type": "none", "cookie": "SERVERID"},
            "health": {"type": "connect", "method": "GET", "path": "/", "host": "", "expect": ""},
            "check": {"inter": "", "rise": "", "fall": ""},
            "forwardfor": mode == "http", "headers": [],
            "timeouts": {"connect": "", "server": "", "check": "", "tunnel": ""},
            "retries": "", "redispatch": False, "servers": [], "advanced": ""}


def empty_frontend(mode="http") -> dict:
    return {"kind": "frontend", "name": "", "mode": mode, "binds": [], "log": True, "forwardfor": False,
            "maxconn": "", "timeouts": {"client": "", "http-request": ""}, "ratelimit": "",
            "force_https": False, "headers": [], "rules": [], "default_backend": "", "advanced": ""}


def empty_server() -> dict:
    return {"name": "", "addr": "", "weight": "", "maxconn": "", "check": True, "backup": False,
            "disabled": False, "ssl": False, "verify_none": True, "sni": "", "send_proxy": "",
            "inter": "", "rise": "", "fall": "", "cookie": "", "extra": ""}


@dataclass
class Parsed:
    model: dict
    owners: dict = field(default_factory=dict)   # body line index (relative) → key
    comments: dict = field(default_factory=dict)  # key → trailing comment


SERVER_FLAGS = {"check", "backup", "disabled", "ssl", "send-proxy", "send-proxy-v2"}
SERVER_ARGS = {"weight", "maxconn", "inter", "rise", "fall", "sni", "cookie", "verify"}


def _parse_server(toks: list[str]) -> dict | None:
    if len(toks) < 3:
        return None
    s = empty_server()
    s.update({"name": toks[1], "addr": toks[2], "check": False, "verify_none": False})
    extra = []
    i = 3
    while i < len(toks):
        t = toks[i]
        if t in SERVER_FLAGS:
            if t == "check":
                s["check"] = True
            elif t == "backup":
                s["backup"] = True
            elif t == "disabled":
                s["disabled"] = True
            elif t == "ssl":
                s["ssl"] = True
            else:
                s["send_proxy"] = "v2" if t.endswith("v2") else "v1"
            i += 1
        elif t in SERVER_ARGS and i + 1 < len(toks):
            v = toks[i + 1]
            if t == "verify":
                if v == "none":
                    s["verify_none"] = True
                else:
                    extra += [t, v]
            elif t == "sni":
                m = re.fullmatch(r"str\((.+)\)", v)
                if m:
                    s["sni"] = m.group(1)
                else:
                    extra += [t, v]
            else:
                s[t] = v
            i += 2
        else:
            extra.append(t)
            i += 1
    s["extra"] = " ".join(extra)
    return s


def _render_server(s: dict) -> str:
    p = ["server", s["name"], s["addr"]]
    if s.get("check"):
        p.append("check")
        for k in ("inter", "rise", "fall"):
            if str(s.get(k) or ""):
                p += [k, str(s[k])]
    if str(s.get("weight") or ""):
        p += ["weight", str(s["weight"])]
    if str(s.get("maxconn") or ""):
        p += ["maxconn", str(s["maxconn"])]
    if s.get("cookie"):
        p += ["cookie", s["cookie"]]
    if s.get("backup"):
        p.append("backup")
    if s.get("ssl"):
        p.append("ssl")
        if s.get("verify_none"):
            p += ["verify", "none"]
        if s.get("sni"):
            p += ["sni", f"str({s['sni']})"]
    if s.get("send_proxy"):
        p.append("send-proxy-v2" if s["send_proxy"] == "v2" else "send-proxy")
    if s.get("disabled"):
        p.append("disabled")
    if s.get("extra"):
        p.append(s["extra"])
    return " ".join(p)


FETCH = {  # haproxy fetch → (cond, takes -i)
    "hdr(host)": "host", "hdr_dom(host)": "host", "req.hdr(host)": "host", "hdr(Host)": "host",
    "path_beg": "path_beg", "path_end": "path_end", "path": "path", "path_reg": "path_reg",
    "src": "src", "method": "method", "req.ssl_sni": "sni", "req_ssl_sni": "sni",
}


def _parse_cond(toks: list[str]) -> dict | None:
    """'hdr(host) -i a.com b.com' → {cond, value[, hname]}"""
    if not toks:
        return None
    f = toks[0]
    rest = [t for t in toks[1:] if t != "-i"]
    if any(t.startswith("-") for t in rest) or not rest:
        return None
    m = re.fullmatch(r"(?:req\.)?hdr\(([^)]+)\)", f)
    if f in FETCH:
        return {"cond": FETCH[f], "value": " ".join(rest), "hname": ""}
    if m and m.group(1).lower() != "host":
        return {"cond": "header", "value": " ".join(rest), "hname": m.group(1)}
    return None


def _render_cond(r: dict) -> str:
    c, v = r["cond"], r["value"]
    return {"host": f"hdr(host) -i {v}", "path_beg": f"path_beg {v}", "path_end": f"path_end {v}",
            "path": f"path {v}", "path_reg": f"path_reg {v}", "header": f"hdr({r.get('hname')}) -i {v}",
            "src": f"src {v}", "method": f"method {v}", "sni": f"req.ssl_sni -i {v}"}[c]


def _render_action(r: dict, cond: str, mode: str) -> tuple[str, str]:
    """→ (group, line). group 'http' = http-request/tcp-request rules, 'be' = use_backend."""
    a, t = r["action"], r.get("target", "")
    if a == "backend":
        return "be", f"use_backend {t} if {cond}"
    if mode == "tcp":
        if a == "deny":
            return "http", f"tcp-request content reject if {cond}"
        raise CfgError(f"rule action '{a}' needs HTTP mode")
    if a == "redirect":
        return "http", f"http-request redirect location {t} code 302 if {cond}"
    if a == "redirect_https":
        return "http", f"http-request redirect scheme https code 301 if {cond}"
    if a == "deny":
        return "http", f"http-request deny if {cond}"
    if a == "allow_only":
        return "http", f"http-request deny if {cond} !{{ src {t} }}"
    if a == "set_header":
        n, _, v = t.partition(":")
        return "http", f"http-request set-header {n.strip()} {v.strip()} if {cond}"
    raise CfgError(f"unknown rule action {a}")


ACT_PATTERNS = [
    ("backend", re.compile(r"^use_backend\s+(\S+)\s+if\s+(.+)$")),
    ("redirect_https", re.compile(r"^http-request\s+redirect\s+scheme\s+https(?:\s+code\s+\d+)?\s+if\s+(.+)$")),
    ("redirect", re.compile(r"^http-request\s+redirect\s+location\s+(\S+)(?:\s+code\s+\d+)?\s+if\s+(.+)$")),
    ("allow_only", re.compile(r"^http-request\s+deny\s+if\s+(\S+)\s+!\{\s*src\s+(\S+)\s*\}$")),
    ("deny", re.compile(r"^(?:http-request\s+deny|tcp-request\s+content\s+reject)\s+if\s+(.+)$")),
    ("set_header", re.compile(r"^http-request\s+set-header\s+(\S+)\s+(\S+)\s+if\s+(.+)$")),
]
RL_RE = [re.compile(r"^stick-table\s+type\s+ip\s+size\s+\S+\s+expire\s+\S+\s+store\s+http_req_rate\(10s\)$"),
         re.compile(r"^http-request\s+track-sc0\s+src$"),
         re.compile(r"^http-request\s+deny\s+deny_status\s+429\s+if\s+\{\s*sc_http_req_rate\(0\)\s+gt\s+(\d+)\s*\}$")]


def _cond_of(expr: str, acls: dict) -> tuple[dict, str | None] | None:
    """A rule condition: one named acl, or one inline { fetch value }."""
    expr = expr.strip()
    m = re.fullmatch(r"\{\s*([^{}]+?)\s*\}", expr)
    if m:
        c = _parse_cond(m.group(1).split())
        return (dict(c, inline=True), None) if c else None
    if re.fullmatch(r"[A-Za-z0-9_.\-]+", expr) and expr in acls:
        c = _parse_cond(acls[expr]["toks"])
        return (dict(c, inline=False, acl=expr), expr) if c else None
    return None


def parse_section(kind: str, name: str, body: list[str]) -> Parsed:
    p = Parsed(empty_backend() if kind == "backend" else empty_frontend())
    m = p.model
    m["name"] = name
    m["mode"] = ""
    if kind == "backend":
        m["forwardfor"] = False
        m["balance"] = ""
        m["health"]["type"] = "connect"
    else:
        m["log"] = False
    lines = [(i, _strip_comment(l)) for i, l in enumerate(body)]
    toks_at = {i: c[0].split() for i, c in lines}
    advanced_idx = set()

    def own(i, key):
        p.owners[i] = key
        if lines[i][1][1]:
            p.comments[key] = lines[i][1][1]

    def first(tok0):
        return [i for i, t in toks_at.items() if t and t[0] == tok0]

    # acl definitions and how often each acl name is used
    acls = {}
    for i, t in toks_at.items():
        if len(t) >= 3 and t[0] == "acl":
            acls.setdefault(t[1], {"idx": [], "toks": t[2:]})["idx"].append(i)
    usage = {n: 0 for n in acls}
    for i, t in toks_at.items():
        if t and t[0] != "acl":
            for w in t:
                for n in re.findall(r"!?([A-Za-z0-9_.\-]+)", w):
                    if n in usage:
                        usage[n] += 1

    for i, t in toks_at.items():
        if not t:
            continue
        d = t[0]
        line = " ".join(t)
        if d == "mode" and len(t) == 2:
            m["mode"] = t[1]; own(i, "mode"); continue
        if d == "timeout" and len(t) == 3 and t[1] in m["timeouts"]:
            m["timeouts"][t[1]] = t[2]; own(i, "timeout " + t[1]); continue
        if line == "option forwardfor":
            m["forwardfor"] = True; own(i, "forwardfor"); continue
        if d in ("http-request", "http-response") and len(t) == 4 and t[1] == "set-header":
            k = f"hdr:{len(m['headers'])}"
            m["headers"].append({"_key": k, "dir": "request" if d == "http-request" else "response",
                                 "name": t[2], "value": t[3]})
            own(i, k); continue
        if kind == "backend":
            if d == "balance" and len(t) >= 2:
                m["balance"] = " ".join(t[1:]); own(i, "balance"); continue
            if d == "cookie" and len(t) >= 3 and t[2] == "insert":
                m["sticky"] = {"type": "cookie", "cookie": t[1]}; own(i, "cookie"); continue
            if d == "option" and len(t) in (2, 4) and t[1] == "httpchk":
                m["health"]["type"] = "http"
                if len(t) == 4:
                    m["health"].update(method=t[2], path=t[3], style="legacy")
                own(i, "hc:option"); continue
            if d == "http-check" and len(t) >= 2 and t[1] == "send":
                kv, j, ok = {}, 2, True
                while j < len(t):
                    if t[j] in ("meth", "uri") and j + 1 < len(t):
                        kv[t[j]] = t[j + 1]; j += 2
                    elif t[j] == "hdr" and j + 2 < len(t) and t[j + 1].lower() == "host":
                        kv["host"] = t[j + 2]; j += 3
                    else:
                        ok = False; break
                if ok:
                    m["health"].update(method=kv.get("meth", "GET"), path=kv.get("uri", "/"), host=kv.get("host", ""))
                    m["health"].pop("style", None)
                    own(i, "hc:send"); continue
            if d == "http-check" and len(t) == 4 and t[1] == "expect" and t[2] in ("status", "rstatus"):
                m["health"]["expect"] = t[3] if t[2] == "status" else "~" + t[3]
                own(i, "hc:expect"); continue
            if d == "retries" and len(t) == 2:
                m["retries"] = t[1]; own(i, "retries"); continue
            if line == "option redispatch":
                m["redispatch"] = True; own(i, "redispatch"); continue
            if d == "default-server" and len(t) >= 3 and set(t[1::2]) <= {"inter", "rise", "fall"} and len(t) % 2 == 1:
                kv = dict(zip(t[1::2], t[2::2]))
                m["check"].update(kv); own(i, "default-server"); continue
            if d == "server":
                s = _parse_server(t)
                if s and s["name"] not in [x["name"] for x in m["servers"]]:
                    s["_key"] = "server:" + s["name"]
                    m["servers"].append(s); own(i, s["_key"]); continue
        else:
            if d == "bind" and len(t) >= 2:
                b = {"_key": f"bind:{len(m['binds'])}", "addr": t[1], "ssl": False, "crt": "", "h2": False, "extra": ""}
                extra, j = [], 2
                while j < len(t):
                    if t[j] == "ssl":
                        b["ssl"] = True; j += 1
                    elif t[j] == "crt" and j + 1 < len(t):
                        b["crt"] = t[j + 1]; j += 2
                    elif t[j] == "alpn" and j + 1 < len(t) and t[j + 1] in ("h2,http/1.1", "h2"):
                        b["h2"] = True; j += 2
                    else:
                        extra.append(t[j]); j += 1
                b["extra"] = " ".join(extra)
                m["binds"].append(b); own(i, b["_key"]); continue
            if line in ("option httplog", "option tcplog"):
                m["log"] = True; own(i, "log"); continue
            if d == "maxconn" and len(t) == 2:
                m["maxconn"] = t[1]; own(i, "maxconn"); continue
            if d == "default_backend" and len(t) == 2:
                m["default_backend"] = t[1]; own(i, "default_backend"); continue
            if re.fullmatch(r"http-request redirect scheme https(?: code \d+)? (?:unless \{ ssl_fc \}|if !\{ ssl_fc \})", line):
                m["force_https"] = True; own(i, "https:redirect"); continue
    # rate limit: all three lines or none
    rl = []
    for k, rx in enumerate(RL_RE):
        hit = [i for i, t in toks_at.items() if t and rx.match(" ".join(t)) and i not in p.owners]
        rl.append(hit[0] if hit else None)
    if kind == "frontend" and all(x is not None for x in rl):
        m["ratelimit"] = RL_RE[2].match(" ".join(toks_at[rl[2]])).group(1)
        for k, i in enumerate(rl):
            own(i, f"rl:{k}")
    # rules (frontend): action lines with one recognizable condition
    if kind == "frontend":
        for i, t in toks_at.items():
            if not t or i in p.owners:
                continue
            line = " ".join(t)
            for action, rx in ACT_PATTERNS:
                mm = rx.match(line)
                if not mm:
                    continue
                g = mm.groups()
                expr = g[0] if action in ("redirect_https", "deny") else (g[0] if action == "allow_only" else g[-1])
                target = {"backend": g[0], "redirect": g[0], "allow_only": g[1] if action == "allow_only" else "",
                          "set_header": f"{g[0]}: {g[1]}" if action == "set_header" else ""}.get(action, "")
                c = _cond_of(expr, acls)
                if not c:
                    break
                cond, acl = c
                if acl and (usage.get(acl, 0) != 1 or len(acls[acl]["idx"]) != 1):
                    break
                k = f"rule:{len(m['rules'])}"
                r = {"_key": k, "cond": cond["cond"], "value": cond["value"], "hname": cond.get("hname", ""),
                     "action": action, "target": target, "inline": cond["inline"], "acl": cond.get("acl", "")}
                m["rules"].append(r)
                own(i, k + ":act")
                if acl:
                    own(acls[acl]["idx"][0], k + ":acl")
                break
    if kind == "frontend" and any(r["cond"] == "sni" for r in m["rules"]):
        for i, t in toks_at.items():
            line = " ".join(t)
            if i not in p.owners and line.startswith("tcp-request inspect-delay "):
                own(i, "sni:delay")
            elif i not in p.owners and line == "tcp-request content accept if { req_ssl_hello_type 1 }":
                own(i, "sni:accept")
        if m["mode"] == "":
            m["mode"] = "tcp"
    adv = []
    for i, l in enumerate(body):
        if i not in p.owners and l.strip():
            adv.append(l.strip())
    m["advanced"] = "\n".join(adv)
    return p


# ---------------------------------------------------------------- rendering a model → keyed lines
RANK_FE = [("bind:", 10), ("mode", 20), ("log", 30), ("forwardfor", 31), ("maxconn", 40), ("timeout ", 41),
           ("rl:0", 50), ("sni:delay", 51), ("rule:", 60), ("rl:1", 70), ("sni:accept", 71), ("rl:2", 72),
           ("https:redirect", 73), ("hdr:", 74), ("default_backend", 90)]
RANK_BE = [("mode", 10), ("balance", 20), ("cookie", 30), ("hc:option", 40), ("hc:send", 41), ("hc:expect", 42),
           ("forwardfor", 50), ("hdr:", 55), ("timeout ", 60), ("retries", 61), ("redispatch", 62),
           ("default-server", 70), ("server:", 80)]


def _rank(kind: str, key: str) -> int:
    if kind == "frontend" and key.startswith("rule:"):
        return 60 if key.endswith(":acl") else (80 if key.endswith(":be") else 75)
    for pre, r in (RANK_FE if kind == "frontend" else RANK_BE):
        if key == pre or (pre.endswith((":", " ")) and key.startswith(pre)):
            return r
    return 99


def _v(x) -> str:
    return str(x if x is not None else "").strip()


def _check(cond: bool, msg: str):
    if not cond:
        raise CfgError(msg)


def _safe(v: str, what: str, rx=SAFE_RE):
    _check(bool(rx.match(v)), f"{what}: '{v}' is not valid")
    return v


def render(m: dict, taken_acls: set[str] | None = None) -> list[tuple[str, str]]:
    """Model → ordered [(key, line)]. Validates every field (raises CfgError)."""
    kind = m["kind"]
    out: list[tuple[str, str]] = []
    mode = m.get("mode") or ""
    _check(mode in ("", "http", "tcp"), "mode must be http or tcp")
    if mode:
        out.append(("mode", f"mode {mode}"))
    for t, v in (m.get("timeouts") or {}).items():
        if _v(v):
            _check(bool(TIME_RE.match(_v(v))), f"timeout {t}: use a number with ms/s/m/h, e.g. 30s")
            out.append(("timeout " + t, f"timeout {t} {_v(v)}"))
    if m.get("forwardfor") and mode != "tcp":
        out.append(("forwardfor", "option forwardfor"))
    for h in m.get("headers") or []:
        _safe(_v(h.get("name")), "header name", HDR_RE)
        _safe(_v(h.get("value")), f"value of header {h.get('name')}")
        _check(mode != "tcp", "headers need HTTP mode")
        d = "http-response" if h.get("dir") == "response" else "http-request"
        out.append((h.get("_key") or f"hdr:new:{id(h)}", f"{d} set-header {_v(h['name'])} {_v(h['value'])}"))
    if kind == "backend":
        b = _v(m.get("balance"))
        if b:
            _check(b.split()[0] in BALANCE, f"unknown load balancing '{b}'")
            out.append(("balance", f"balance {b}"))
        st = m.get("sticky") or {}
        if st.get("type") == "cookie":
            _check(mode != "tcp", "cookie stickiness needs HTTP mode")
            c = _safe(_v(st.get("cookie")) or "SERVERID", "cookie name", HDR_RE)
            out.append(("cookie", f"cookie {c} insert indirect nocache"))
        hc = m.get("health") or {}
        if hc.get("type") == "http":
            _check(mode != "tcp", "an HTTP health check needs HTTP mode")
            meth = _v(hc.get("method")) or "GET"
            _check(meth in ("GET", "HEAD", "OPTIONS", "POST"), "health check method")
            path = _v(hc.get("path")) or "/"
            _check(path.startswith("/") and bool(SAFE_RE.match(path)), "health check path must start with /")
            if hc.get("style") == "legacy" and not _v(hc.get("host")):
                out.append(("hc:option", f"option httpchk {meth} {path}"))
            else:
                out.append(("hc:option", "option httpchk"))
                send = f"http-check send meth {meth} uri {path}"
                if _v(hc.get("host")):
                    _safe(_v(hc["host"]), "health check Host", HOST_RE)
                    send += f" hdr Host {_v(hc['host'])}"
                out.append(("hc:send", send))
            ex = _v(hc.get("expect"))
            if ex:
                if ex.startswith("~"):
                    out.append(("hc:expect", f"http-check expect rstatus {_safe(ex[1:], 'expected status')}"))
                else:
                    _check(bool(re.fullmatch(r"\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*", ex)), "expected status: e.g. 200 or 200-399")
                    out.append(("hc:expect", f"http-check expect status {ex}"))
        if _v(m.get("retries")):
            _check(_v(m["retries"]).isdigit(), "retries must be a number")
            out.append(("retries", f"retries {_v(m['retries'])}"))
        if m.get("redispatch"):
            out.append(("redispatch", "option redispatch"))
        ck = {k: _v(v) for k, v in (m.get("check") or {}).items() if _v(v)}
        if ck:
            for k, v in ck.items():
                _check(k in ("inter", "rise", "fall"), "check setting")
                _check(bool(TIME_RE.match(v)) if k == "inter" else v.isdigit(), f"check {k}: '{v}'")
            out.append(("default-server", "default-server " + " ".join(f"{k} {v}" for k, v in ck.items())))
        names = set()
        for s in m.get("servers") or []:
            s = {**empty_server(), **s}
            _safe(_v(s["name"]), "server name", NAME_RE)
            _check(s["name"] not in names, f"server name {s['name']} is used twice")
            names.add(s["name"])
            _check(bool(SERVER_ADDR_RE.match(_v(s["addr"]))), f"server {s['name']}: address must be host:port")
            for k in ("weight", "maxconn", "rise", "fall"):
                _check(not _v(s.get(k)) or _v(s[k]).isdigit(), f"server {s['name']}: {k} must be a number")
            _check(not _v(s.get("inter")) or bool(TIME_RE.match(_v(s["inter"]))), f"server {s['name']}: check interval")
            if _v(s.get("sni")):
                _safe(_v(s["sni"]), "SNI", HOST_RE)
            if _v(s.get("cookie")):
                _safe(_v(s["cookie"]), "server cookie", NAME_RE)
            if _v(s.get("extra")):
                _check(bool(re.fullmatch(r"[^#\n{}]{1,300}", _v(s["extra"]))), f"server {s['name']}: extra options")
            st_cookie = (m.get("sticky") or {}).get("type") == "cookie" and not s.get("cookie") and not s.get("_key")
            if st_cookie:
                s["cookie"] = s["name"]
            out.append((s.get("_key") or "server:" + s["name"], _render_server(s)))
    else:
        if m.get("log"):
            out.append(("log", "option tcplog" if mode == "tcp" else "option httplog"))
        if _v(m.get("maxconn")):
            _check(_v(m["maxconn"]).isdigit(), "maxconn must be a number")
            out.append(("maxconn", f"maxconn {_v(m['maxconn'])}"))
        binds = m.get("binds") or []
        for k, b in enumerate(binds):
            a = _v(b.get("addr"))
            _check(bool(ADDR_RE.match(a)), f"listen address '{a}' — use e.g. *:80 or 10.0.0.5:8080")
            line = f"bind {a}"
            if b.get("ssl"):
                crt = _v(b.get("crt"))
                _check(crt.startswith("/") and bool(SAFE_RE.match(crt)), "HTTPS needs a certificate path (a .pem file or folder)")
                line += f" ssl crt {crt}"
                if b.get("h2"):
                    line += " alpn h2,http/1.1"
            if _v(b.get("extra")):
                _check(bool(re.fullmatch(r"[^#\n{}]{1,300}", _v(b["extra"]))), "bind options")
                line += " " + _v(b["extra"])
            out.append((b.get("_key") or f"bind:new:{k}", line))
        if m.get("force_https"):
            _check(mode != "tcp", "force HTTPS needs HTTP mode")
            out.append(("https:redirect", "http-request redirect scheme https code 301 unless { ssl_fc }"))
        rl = _v(m.get("ratelimit"))
        if rl:
            _check(rl.isdigit() and int(rl) > 0, "rate limit: requests per 10 seconds per IP")
            _check(mode != "tcp", "rate limit needs HTTP mode")
            out += [("rl:0", "stick-table type ip size 100k expire 30s store http_req_rate(10s)"),
                    ("rl:1", "http-request track-sc0 src"),
                    ("rl:2", f"http-request deny deny_status 429 if {{ sc_http_req_rate(0) gt {rl} }}")]
        rules = m.get("rules") or []
        if mode == "tcp" and any(r.get("cond") == "sni" for r in rules):
            out += [("sni:delay", "tcp-request inspect-delay 5s"),
                    ("sni:accept", "tcp-request content accept if { req_ssl_hello_type 1 }")]
        used = set(taken_acls or set())
        for r in rules:
            used.add(r.get("acl") or "")
        for k, r in enumerate(rules):
            c, v = r.get("cond"), _v(r.get("value"))
            _check(c in CONDS, f"rule {k + 1}: unknown condition")
            _check(r.get("action") in ACTIONS, f"rule {k + 1}: unknown action")
            _check(bool(v), f"rule {k + 1}: enter a value")
            if c == "host":
                for h in v.split():
                    _safe(h, f"rule {k + 1} hostname", HOST_RE)
            elif c in ("path_beg", "path", "path_end"):
                for x in v.split():
                    _safe(x, f"rule {k + 1} path")
                _check(c == "path_end" or all(x.startswith("/") for x in v.split()), f"rule {k + 1}: paths start with /")
            elif c == "src":
                _safe(v.replace(" ", ","), f"rule {k + 1} IP/CIDR", CIDR_RE)
            elif c == "header":
                _safe(_v(r.get("hname")), f"rule {k + 1} header name", HDR_RE)
                _safe(v, f"rule {k + 1} header value")
            elif c == "method":
                _check(bool(re.fullmatch(r"[A-Z]{3,10}( [A-Z]{3,10})*", v)), f"rule {k + 1}: method like GET or POST")
            elif c == "sni":
                for h in v.split():
                    _safe(h, f"rule {k + 1} SNI", HOST_RE)
                _check(mode == "tcp", f"rule {k + 1}: SNI routing is for TCP mode (HTTP uses Host)")
            else:
                _safe(v, f"rule {k + 1} value")
            if c in ("host", "path_beg", "path", "path_end", "path_reg", "header", "method"):
                _check(mode != "tcp", f"rule {k + 1}: this condition needs HTTP mode (TCP can use SNI or source IP)")
            t = _v(r.get("target"))
            a = r["action"]
            if a == "backend":
                _safe(t, f"rule {k + 1} backend", NAME_RE)
            elif a == "redirect":
                _check(bool(re.fullmatch(r"https?://\S+|/\S*", t)) and bool(SAFE_RE.match(t)), f"rule {k + 1}: redirect to a URL")
            elif a == "allow_only":
                _safe(t.replace(" ", ","), f"rule {k + 1} allowed IPs", CIDR_RE)
            elif a == "set_header":
                n, sep, hv = t.partition(":")
                _check(bool(sep) and bool(HDR_RE.match(n.strip())) and bool(SAFE_RE.match(hv.strip())),
                       f"rule {k + 1}: header as 'Name: value'")
            key = r.get("_key") or f"rule:new{k}"
            if r.get("inline"):
                cond = "{ " + _render_cond(r) + " }"
            else:
                acl = r.get("acl") or ""
                if not acl:
                    base = "gwc_" + re.sub(r"[^a-z0-9]+", "_", f"{c}_{v.split()[0]}".lower()).strip("_")[:40]
                    acl, n = base, 2
                    while acl in used:
                        acl, n = f"{base}_{n}", n + 1
                    used.add(acl)
                    r["acl"] = acl
                out.append((key + ":acl", f"acl {acl} {_render_cond(r)}"))
                cond = acl
            g, line = _render_action(r, cond, mode)
            out.append((key + (":be" if g == "be" else ":act"), line))
        if _v(m.get("default_backend")):
            _safe(_v(m["default_backend"]), "default backend", NAME_RE)
            out.append(("default_backend", f"default_backend {_v(m['default_backend'])}"))
    adv = (m.get("advanced") or "").strip("\n")
    for l in adv.splitlines():
        tk = l.split()
        _check(not (tk and tk[0] in SECTION_KW), f"advanced line '{l.strip()}' would start a new section")
    return out


# ---------------------------------------------------------------- parse whole file
def parse(text: str) -> dict:
    lines = text.split("\n")
    out = {"frontends": [], "backends": [], "other": []}
    for s in sections(lines):
        if s.kind in ("frontend", "backend"):
            p = parse_section(s.kind, s.name, lines[s.start + 1:s.end])
            mdl = p.model
            mdl["orig_name"] = s.name
            (out["frontends"] if s.kind == "frontend" else out["backends"]).append(mdl)
        else:
            out["other"].append({"kind": s.kind, "name": s.name})
    return out


def _act_key(k: str) -> bool:
    return k.startswith("rule:") and (k.endswith(":act") or k.endswith(":be"))


def _merge(kind: str, body: list[str], parsed: Parsed, new: dict) -> list[str]:
    """Merge the rendered new model into the original body lines."""
    # parsed rule keys are 'rule:N:act' for both groups; normalise to the group the new render uses
    owners = dict(parsed.owners)
    for i, k in owners.items():
        if k.endswith(":act") and k.startswith("rule:") and _norm(body[i])[:1] == ["use_backend"]:
            owners[i] = k[:-4] + ":be"
    rendered = render(new, new.get("_taken"))
    want = dict(rendered)
    order = [k for k, _ in rendered]
    orig_adv = [i for i, l in enumerate(body) if i not in owners and l.strip()]
    orig_adv_text = "\n".join(body[i].strip() for i in orig_adv)
    new_adv = [l.strip() for l in (new.get("advanced") or "").splitlines() if l.strip()]
    adv_changed = "\n".join(new_adv) != orig_adv_text
    out: list[tuple[str | None, str]] = []   # (key or None, line)
    done = set()
    groups = {"act": [k for k in order if k.startswith("rule:") and k.endswith(":act")],
              "be": [k for k in order if k.startswith("rule:") and k.endswith(":be")]}
    adv_placed = False

    def line_for(k, orig=None):
        nl = IND + want[k]
        if orig is not None:
            o, n = _norm(orig), want[k].split()
            same = o == n or (k.startswith(("server:", "bind:")) and o[:3] == n[:3] and _params(o[3:]) == _params(n[3:]))
            if same:
                return orig
        c = parsed.comments.get(k)
        return nl + ("  " + c if c else "")

    for i, l in enumerate(body):
        k = owners.get(i)
        if k is None:
            if not l.strip():
                out.append((None, l))
            elif not adv_changed:
                out.append((None, l))
            elif not adv_placed:
                out += [(None, IND + x) for x in new_adv]
                adv_placed = True
            continue
        g = "act" if (k.startswith("rule:") and k.endswith(":act")) else "be" if (k.startswith("rule:") and k.endswith(":be")) else None
        if g:
            if g + "!" in done:
                continue
            done.add(g + "!")
            for nk in groups[g]:
                orig_i = next((j for j, kk in owners.items() if kk == nk), None)
                out.append((nk, line_for(nk, body[orig_i] if orig_i is not None else None)))
                done.add(nk)
            continue
        if k in want and k not in done:
            out.append((k, line_for(k, l)))
            done.add(k)
    if adv_changed and not adv_placed and new_adv:
        out += [(None, IND + x) for x in new_adv]
    # insert what's still missing next to its kind
    for k in order:
        if k in done:
            continue
        r = _rank(kind, k)
        pos = 0
        for j, (kk, _) in enumerate(out):
            if kk is not None and _rank(kind, kk) <= r:
                pos = j + 1
        out.insert(pos, (k, IND + want[k]))
        done.add(k)
    # drop blank lines at the very end of the body
    res = [l for _, l in out]
    while res and not res[-1].strip():
        res.pop()
    return res


def _params(toks: list[str]) -> list[tuple]:
    """Server/bind options as an order-independent set ('weight 100' stays a pair)."""
    out, i = [], 0
    while i < len(toks):
        if toks[i] in SERVER_ARGS or toks[i] in ("crt", "alpn") and i + 1 < len(toks):
            out.append((toks[i], toks[i + 1] if i + 1 < len(toks) else "")); i += 2
        else:
            out.append((toks[i],)); i += 1
    return sorted(out)


def _header(kind: str, name: str, rest: str = "") -> str:
    return f"{kind} {name}{rest}"


def references(text: str, backend: str) -> list[str]:
    """Sections that send traffic to this backend (default_backend / use_backend)."""
    lines = text.split("\n")
    refs = []
    for s in sections(lines):
        for l in lines[s.start + 1:s.end]:
            t = _norm(l)
            if len(t) >= 2 and t[0] in ("default_backend", "use_backend") and t[1] == backend:
                refs.append(f"{s.kind} {s.name}")
                break
    return refs


def apply_ops(text: str, ops: list[dict]) -> str:
    """Apply [{op: upsert|delete, kind, orig_name?, model?/name?}] in order; returns new text."""
    for op in ops:
        kind = op.get("kind")
        _check(kind in ("frontend", "backend"), "kind must be frontend or backend")
        lines = text.split("\n")
        secs = [s for s in sections(lines) if s.kind in ("frontend", "backend", "listen")]
        if op.get("op") == "delete":
            name = op.get("name", "")
            s = next((x for x in secs if x.kind == kind and x.name == name), None)
            _check(s is not None, f"{kind} {name} not found")
            if kind == "backend":
                refs = [r for r in references(text, name) if r != f"backend {name}"]
                _check(not refs, f"backend {name} is still used by {', '.join(refs)} — change those first")
            start = s.start
            while start > 0 and lines[start - 1].startswith("#"):   # its comment block
                start -= 1
            end = s.end
            while end < len(lines) and not lines[end].strip():
                end += 1
            del lines[start:end]
            text = "\n".join(lines)
            continue
        _check(op.get("op") == "upsert", "op must be upsert or delete")
        m = dict(op.get("model") or {})
        m["kind"] = kind
        name = _v(m.get("name"))
        _safe(name, f"{kind} name", NAME_RE)
        orig = op.get("orig_name") or ""
        clash = next((x for x in secs if x.name == name and not (x.kind == kind and x.name == orig)
                      and x.kind in (kind, "listen")), None)
        _check(clash is None, f"a {clash.kind if clash else ''} named {name} already exists")
        if orig:
            s = next((x for x in secs if x.kind == kind and x.name == orig), None)
            _check(s is not None, f"{kind} {orig} not found (changed meanwhile?)")
            body = lines[s.start + 1:s.end]
            parsed = parse_section(kind, orig, body)
            taken = {t[1] for t in (_norm(l) for l in body) if len(t) > 1 and t[0] == "acl"}
            m = _with_acls(m, parsed, taken)
            new_body = _merge(kind, body, parsed, m)
            lines[s.start:s.end] = [_header(kind, name, s.header_rest)] + new_body
            text = "\n".join(lines)
            if name != orig and kind == "backend":
                text = rename_backend_refs(text, orig, name)
        else:
            _check(kind != "frontend" or bool(m.get("binds")), "a new frontend needs at least one listen address")
            rendered = sorted(render(m), key=lambda kv: _rank(kind, kv[0]))
            adv = [l.strip() for l in (m.get("advanced") or "").splitlines() if l.strip()]
            block = [_header(kind, name)] + [IND + l for _, l in rendered] + [IND + a for a in adv]
            # new frontends go after the last frontend, new backends at the end
            last = [x for x in secs if x.kind == kind]
            if kind == "frontend" and last:
                at = last[-1].end
                tail = [""] if at < len(lines) and lines[at].strip() else []
                lines[at:at] = [""] + block + tail
            else:
                while lines and not lines[-1].strip():
                    lines.pop()
                lines += [""] + block + [""]
            text = "\n".join(lines)
            if not text.endswith("\n"):
                text += "\n"
    return text if text.endswith("\n") else text + "\n"


def _with_acls(m: dict, parsed: Parsed, taken: set[str]) -> dict:
    """Keep existing rules' acl names; new rules get fresh ones that don't clash."""
    m = {**m, "rules": [dict(r) for r in (m.get("rules") or [])]}
    known = {r["_key"]: r for r in parsed.model.get("rules", [])}
    for r in m["rules"]:
        o = known.get(r.get("_key") or "")
        if o:
            r["acl"] = o.get("acl", "")
            r["inline"] = o.get("inline", False)
        else:
            r["_key"] = None
            r["acl"] = ""
            r["inline"] = False
    m["_taken"] = taken
    return m


def rename_backend_refs(text: str, old: str, new: str) -> str:
    out = []
    for l in text.split("\n"):
        t = _norm(l)
        if len(t) >= 2 and t[0] in ("default_backend", "use_backend") and t[1] == old:
            l = re.sub(rf"(\b{t[0]}\s+){re.escape(old)}(?=\s|$)", rf"\g<1>{new}", l, count=1)
        out.append(l)
    return "\n".join(out)


def find_section(text: str, kind: str, name: str) -> dict | None:
    d = parse(text)
    return next((x for x in d["frontends" if kind == "frontend" else "backends"] if x["name"] == name), None)


def routed_hosts(text: str) -> dict[str, str]:
    """hostname → 'frontend fe: backend' for every host rule, to warn about duplicates."""
    out = {}
    for fe in parse(text)["frontends"]:
        for r in fe["rules"]:
            if r["cond"] == "host":
                for h in r["value"].split():
                    out[h.lower()] = f"{fe['name']} → {r.get('target') or r['action']}"
    return out


def bind_ports(text: str) -> dict[str, str]:
    """'port' → 'frontend fe' for every bind line in frontends/listens."""
    out = {}
    lines = text.split("\n")
    for s in sections(lines):
        if s.kind in ("frontend", "listen"):
            for l in lines[s.start + 1:s.end]:
                t = _norm(l)
                if len(t) >= 2 and t[0] == "bind":
                    for a in t[1].split(","):
                        p = a.rsplit(":", 1)[-1]
                        out[p] = f"{s.kind} {s.name}"
    return out
