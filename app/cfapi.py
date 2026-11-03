"""Cloudflare API: tunnel edge health and DNS route checks per account."""
from __future__ import annotations

import asyncio
import base64
import secrets
import os
import fnmatch
import time

import httpx

from .config import CFAccount, Settings

API = os.environ.get("GWC_CF_API", "https://api.cloudflare.com/client/v4")


class CFError(Exception):
    pass


class _Cache:
    def __init__(self):
        self._d: dict = {}

    def get(self, key, ttl):
        v = self._d.get(key)
        if v and time.time() - v[0] < ttl:
            return v[1]
        return None

    def put(self, key, val):
        self._d[key] = (time.time(), val)

    def drop_prefix(self, prefix):
        for k in [k for k in self._d if k[0] == prefix]:
            self._d.pop(k, None)


class Cloudflare:
    def __init__(self, s: Settings):
        self.s = s
        self.http = httpx.AsyncClient(base_url=API, timeout=15)
        self.cache = _Cache()

    async def close(self):
        await self.http.aclose()

    async def _req(self, acc: CFAccount, method: str, path: str, **kw):
        if not acc.api_token:
            raise CFError(f"no API token configured for account {acc.name}")
        r = await self.http.request(method, path, headers={"Authorization": f"Bearer {acc.api_token}"}, **kw)
        try:
            j = r.json()
        except ValueError:
            raise CFError(f"Cloudflare API HTTP {r.status_code}")
        if not j.get("success"):
            errs = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in j.get("errors") or [])
            raise CFError(errs or f"Cloudflare API HTTP {r.status_code}")
        return j

    async def _paged(self, acc, path, params=None, per_page=100):
        out, page = [], 1
        while True:
            j = await self._req(acc, "GET", path, params={**(params or {}), "page": page, "per_page": per_page})
            out.extend(j.get("result") or [])
            info = j.get("result_info") or {}
            if page >= int(info.get("total_pages") or 1):
                return out
            page += 1

    # --- tunnels ------------------------------------------------------------
    async def tunnels(self, acc: CFAccount) -> list[dict]:
        key = ("tun", acc.name)
        c = self.cache.get(key, 20)
        if c is not None:
            return c
        rows = await self._paged(acc, f"/accounts/{acc.account_id}/cfd_tunnel", {"is_deleted": "false"})
        res = [{
            "id": t.get("id"), "name": t.get("name"), "status": t.get("status"),
            "created_at": t.get("created_at"), "conns_active_at": t.get("conns_active_at"),
            "remote_config": t.get("remote_config"),
            "connections": [{
                "colo": c.get("colo_name"), "origin_ip": c.get("origin_ip"),
                "version": c.get("client_version"), "opened_at": c.get("opened_at"),
                "pending_reconnect": c.get("is_pending_reconnect"),
            } for c in (t.get("connections") or [])],
        } for t in rows]
        self.cache.put(key, res)
        return res

    async def all_tunnels(self) -> dict:
        async def one(acc):
            try:
                return acc.name, {"tunnels": await self.tunnels(acc), "error": None}
            except (CFError, httpx.HTTPError) as e:
                return acc.name, {"tunnels": [], "error": str(e) or type(e).__name__}
        pairs = await asyncio.gather(*(one(a) for a in self.s.cf_accounts.values()))
        return dict(pairs)

    # --- DNS ------------------------------------------------------------------
    async def zones(self, acc: CFAccount) -> list[dict]:
        key = ("zones", acc.name)
        c = self.cache.get(key, 600)
        if c is not None:
            return c
        rows = await self._paged(acc, "/zones", {"account.id": acc.account_id}, per_page=50)
        res = [{"id": z["id"], "name": z["name"]} for z in rows]
        self.cache.put(key, res)
        return res

    async def records(self, acc: CFAccount, zone_id: str) -> list[dict]:
        key = ("dns", acc.name, zone_id)
        c = self.cache.get(key, 60)
        if c is not None:
            return c
        rows = await self._paged(acc, f"/zones/{zone_id}/dns_records", per_page=500)
        res = [{"id": r["id"], "type": r["type"], "name": r["name"], "content": r.get("content", ""),
                "proxied": r.get("proxied")} for r in rows]
        self.cache.put(key, res)
        return res

    @staticmethod
    def _zone_for(host: str, zones: list[dict]) -> dict | None:
        host = (host[2:] if host.startswith("*.") else host).lower()
        best = None
        for z in zones:
            n = z["name"].lower()
            if host == n or host.endswith("." + n):
                if not best or len(n) > len(best["name"]):
                    best = z
        return best

    async def route_report(self, acc: CFAccount, tunnel_id: str, hostnames: list[str]) -> dict:
        """For each ingress hostname: does DNS point at this tunnel? Plus orphans."""
        target = f"{tunnel_id}.cfargotunnel.com".lower()
        zones = await self.zones(acc)
        report, zone_ids = [], set()
        for h in hostnames:
            z = self._zone_for(h, zones)
            if not z:
                report.append({"hostname": h, "status": "no_zone", "detail": "zone not in this account / token"})
                continue
            zone_ids.add(z["id"])
            recs = [r for r in await self.records(acc, z["id"]) if r["name"].lower() == h.lower()]
            if not recs:
                # wildcard record covering it?
                wild = [r for r in await self.records(acc, z["id"])
                        if r["name"].startswith("*.") and fnmatch.fnmatch(h.lower(), r["name"].lower())]
                if wild and wild[0]["content"].lower() == target:
                    report.append({"hostname": h, "status": "ok", "detail": f"via {wild[0]['name']}", "zone": z["name"]})
                else:
                    report.append({"hostname": h, "status": "missing", "detail": "no DNS record", "zone": z["name"]})
                continue
            r = recs[0]
            if r["type"] == "CNAME" and r["content"].lower() == target:
                st = "ok" if r["proxied"] else "not_proxied"
                report.append({"hostname": h, "status": st, "detail": "CNAME → this tunnel"
                               + ("" if r["proxied"] else " (DNS only, must be proxied)"), "zone": z["name"]})
            elif r["type"] == "CNAME" and r["content"].lower().endswith(".cfargotunnel.com"):
                report.append({"hostname": h, "status": "other_tunnel",
                               "detail": f"points to {r['content'].split('.')[0][:8]}… (another tunnel)", "zone": z["name"]})
            else:
                report.append({"hostname": h, "status": "conflict",
                               "detail": f"{r['type']} {r['content']}", "zone": z["name"]})
        orphans = []
        for zid in zone_ids:
            hset = {h.lower() for h in hostnames}
            for r in await self.records(acc, zid):
                if r["type"] == "CNAME" and r["content"].lower() == target and r["name"].lower() not in hset:
                    orphans.append(r["name"])
        return {"routes": report, "orphans": sorted(orphans)}

    async def route_dns(self, acc: CFAccount, tunnel_id: str, hostname: str, overwrite: bool = False) -> str:
        """Create or repoint a proxied CNAME hostname -> <tunnel>.cfargotunnel.com."""
        target = f"{tunnel_id}.cfargotunnel.com"
        z = self._zone_for(hostname, await self.zones(acc))
        if not z:
            raise CFError(f"no zone for {hostname} in account {acc.name}")
        recs = [r for r in await self.records(acc, z["id"]) if r["name"].lower() == hostname.lower()]
        body = {"type": "CNAME", "name": hostname, "content": target, "proxied": True,
                "comment": "managed by gwconsole"}
        if recs:
            r = recs[0]
            if r["type"] != "CNAME":
                raise CFError(f"{hostname} already has a {r['type']} record ({r['content']}); refusing to overwrite")
            if r["content"].lower() == target.lower() and r.get("proxied"):
                return f"{hostname} already routed to this tunnel"
            if not overwrite and r["content"].lower() != target.lower():
                what = (f"another tunnel ({r['content'].split('.')[0][:8]}…)" if r["content"].endswith(".cfargotunnel.com")
                        else r["content"])
                raise CFError(f"{hostname} already points to {what}; not changed. Use 'Fix route' on the Tunnels page to repoint it")
            await self._req(acc, "PATCH", f"/zones/{z['id']}/dns_records/{r['id']}", json=body)
            msg = f"updated CNAME {hostname} → {target}"
        else:
            await self._req(acc, "POST", f"/zones/{z['id']}/dns_records", json=body)
            msg = f"created CNAME {hostname} → {target}"
        self.cache.drop_prefix("dns")
        return msg

    # --- tunnel lifecycle -----------------------------------------------------
    async def create_tunnel(self, acc: CFAccount, name: str) -> tuple[str, str]:
        """Create a locally-managed tunnel. Returns (tunnel_id, tunnel_secret_b64)."""
        secret = base64.b64encode(secrets.token_bytes(32)).decode()
        j = await self._req(acc, "POST", f"/accounts/{acc.account_id}/cfd_tunnel",
                            json={"name": name, "config_src": "local", "tunnel_secret": secret})
        tid = (j.get("result") or {}).get("id")
        if not tid:
            raise CFError("Cloudflare did not return a tunnel id")
        self.cache.drop_prefix("tun")
        return tid, secret

    async def delete_tunnel(self, acc: CFAccount, tunnel_id: str, cleanup_connections: bool = True) -> str:
        if cleanup_connections:
            try:
                await self._req(acc, "DELETE", f"/accounts/{acc.account_id}/cfd_tunnel/{tunnel_id}/connections")
            except CFError:
                pass  # nothing to clean up / not permitted — delete below reports the real problem
        await self._req(acc, "DELETE", f"/accounts/{acc.account_id}/cfd_tunnel/{tunnel_id}")
        self.cache.drop_prefix("tun")
        return f"deleted tunnel {tunnel_id} in Cloudflare account {acc.name}"

    async def records_for_tunnel(self, acc: CFAccount, tunnel_id: str) -> list[dict]:
        target = f"{tunnel_id}.cfargotunnel.com".lower()
        out = []
        for z in await self.zones(acc):
            for r in await self.records(acc, z["id"]):
                if r["type"] == "CNAME" and r["content"].lower() == target:
                    out.append({**r, "zone_id": z["id"], "zone": z["name"]})
        return out

    async def delete_records_for_tunnel(self, acc: CFAccount, tunnel_id: str, only: str | None = None) -> list[str]:
        """Delete CNAMEs pointing at this tunnel (optionally only the one named `only`)."""
        done = []
        self.cache.drop_prefix("dns")
        for r in await self.records_for_tunnel(acc, tunnel_id):
            if only and r["name"].lower() != only.lower():
                continue
            await self._req(acc, "DELETE", f"/zones/{r['zone_id']}/dns_records/{r['id']}")
            done.append(r["name"])
        self.cache.drop_prefix("dns")
        return done
