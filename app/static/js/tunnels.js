/* Gateway Console web UI — Tunnels page: every cloudflared service (auto-discovered), Cloudflare
 * edge status, ingress rules + DNS checks, create/delete tunnels, add/remove hostnames,
 * and "Edit config" which opens the side-panel editor. */
"use strict";

const SERVICE_HINT = `<div class="hint">e.g. <code>http://10.10.10.20:80</code> · <code>https://10.10.10.20:443</code> · <code>tcp://10.10.10.20:25565</code> · <code>ssh://10.10.10.20:22</code></div>`;

PAGES.tunnels = {
  every: 15,
  mount(v) {
    setHeader("Tunnels", "cloudflared services · Cloudflare edge · ingress & DNS routes");
    v.innerHTML = `<div id="tunAcc"></div><div id="tunNodes"><div class="panel"><div class="empty">Loading…</div></div></div><div id="tunUnmanaged"></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
  },
  async load() {
    const d = await api("/api/tunnels");
    if (S.page !== "tunnels") return;
    S.cache.tun = d;
    const accErr = Object.entries(d.accounts).filter(([, a]) => a.error);
    $("#tunAcc").innerHTML = accErr.length ? `<div class="panel"><div class="bd">${accErr.map(([n, a]) => `<div>${pill("warn", "CF API")} <b>${esc(n)}</b> <span class="muted">${esc(a.error)}</span></div>`).join("")}</div></div>` : "";
    $("#tunNodes").innerHTML = d.nodes.map((n) => {
      if (n.error) return `<div class="panel"><div class="hd"><h2>${esc(n.node)}</h2>${pill("crit", "unreachable")}</div><div class="bd muted">${esc(n.error)}</div></div>`;
      return `<div class="panel"><div class="hd"><h2>${esc(n.node)}</h2><span class="meta mono">${esc(n.host)}</span>${n.site ? `<span class="tag">${esc(n.site)}</span>` : ""}<span class="meta">${esc(n.version)}</span>
          <div class="acts"><button class="btn sm pri op" data-act="new" data-node="${esc(n.node)}">+ New tunnel</button></div></div>
        <div class="bd" style="display:flex;flex-direction:column;gap:14px">${n.tunnels.map((t) => this.tunnel(n, t)).join("") || `<div class="empty">No cloudflared services found on this node.</div>`}</div></div>`;
    }).join("") || `<div class="panel"><div class="empty">No cloudflared nodes yet.${S.role === "superadmin" ? ` <a href="#/settings/nodes">Add one in Settings → Nodes</a>.` : ""}</div></div>`;
    const um = d.unmanaged || [];
    $("#tunUnmanaged").innerHTML = um.length ? `<div class="panel"><div class="hd"><h2>In Cloudflare, not on a managed node</h2>
        <span class="meta">Tunnels in your accounts that no managed cloudflared runs. Live ones run somewhere else (another server / site).</span></div>
      <div class="bd flush tbl-wrap"><table><thead><tr><th>Account</th><th>Tunnel</th><th>Status</th><th>Connections</th><th>Created</th><th></th></tr></thead><tbody>
      ${um.map((t) => {
        const ips = [...new Set(t.connections.map((c) => c.origin_ip).filter(Boolean))];
        return `<tr><td>${esc(t.account)}</td><td><b>${esc(t.name)}</b><div class="sub mono">${esc(t.id)}</div></td><td>${pill(edgeClass(t.status), t.status)}</td>
          <td>${t.connections.length ? `${t.connections.length} from <span class="mono small">${esc(ips.join(", "))}</span>` : `<span class="muted">none</span>`}</td>
          <td class="small">${esc((t.created_at || "").slice(0, 10))}</td>
          <td>${t.connections.length ? `<span class="sub">running elsewhere</span>` : `<button class="btn sm danger op" data-act="cfdel" data-acc="${esc(t.account)}" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Delete</button>`}</td></tr>`;
      }).join("")}</tbody></table></div></div>` : "";
  },
  find(node, name) {
    const n = S.cache.tun.nodes.find((x) => x.node === node);
    return { n, t: n?.tunnels.find((x) => x.name === name) };
  },
  tunnel(n, t) {
    const e = t.edge, ref = `${encodeURIComponent(n.node)}/${encodeURIComponent(t.name)}`;
    const routes = Object.fromEntries((t.dns?.routes || []).map((r) => [r.hostname, r]));
    const ing = t.config.ingress;
    const local = !t.remote;
    return `<div class="card" style="gap:12px">
      <div class="t" style="flex-wrap:wrap">${esc(t.name)} <span class="muted mono small">${esc(t.unit)}</span>${t.remote ? pill("info", "token-run") : ""}
        <span class="r row">${pill(svcClass(t.service.active), "local: " + t.service.active)} ${e ? pill(edgeClass(e.status), "edge: " + e.status) : pill("mute", t.edge_error ? "edge: API error" : "edge: not found")}</span></div>
      <div class="row small">
        ${local ? `<button class="btn sm pri op" data-act="addhost" data-ref="${ref}">+ Hostname</button>
        <button class="btn sm" data-act="test" data-ref="${ref}">Test rule</button>
        <button class="btn sm" data-act="edit" data-ref="${ref}">Edit config</button>` : ""}
        <button class="btn sm" data-act="logs" data-ref="${ref}">Logs</button>
        <span class="grow"></span>
        ${t.service.active === "active" ? `<button class="btn sm op" data-act="svc" data-a="restart" data-ref="${ref}">Restart</button><button class="btn sm op" data-act="svc" data-a="stop" data-ref="${ref}">Stop</button>`
          : `<button class="btn sm pri op" data-act="svc" data-a="start" data-ref="${ref}">Start</button>`}
        <button class="btn sm danger op" data-act="del" data-ref="${ref}">Delete</button>
      </div>
      <dl class="kv"><dt>Tunnel</dt><dd class="mono">${esc((e && e.id) || t.config.tunnel || "–")}${e && t.config.tunnel && e.id !== t.config.tunnel ? ` <span class="muted">(${esc(t.config.tunnel)})</span>` : ""}</dd>
        <dt>Account</dt><dd>${t.cf_account ? esc(t.cf_account) + (t.cf_account_auto ? ` <span class="sub">(auto-matched)</span>` : "") : `<span class="muted">not found in configured accounts</span>`}</dd>
        ${local ? `<dt>Config</dt><dd class="mono">${esc(t.config_path)}</dd>` : ""}
        <dt>Running since</dt><dd>${esc(t.service.since || "–")}${t.service.restarts ? ` · ${t.service.restarts} restarts` : ""}</dd>
        ${t.ready_connections != null ? `<dt>Ready conns</dt><dd>${t.ready_connections} (metrics)</dd>` : ""}
        ${e ? `<dt>Edge conns</dt><dd>${e.connections.map((c) => `<span class="chip" title="${esc(c.origin_ip + " · " + c.version + " · opened " + c.opened_at)}">${esc(c.colo)}</span>`).join("") || "none"}
          ${e.connections[0] ? `<span class="sub">v${esc(e.connections[0].version)} from ${esc(e.connections[0].origin_ip)}</span>` : ""}</dd>` : ""}
        ${t.config.error ? `<dt>Config</dt><dd style="color:var(--crit)">${esc(t.config.error)}</dd>` : ""}</dl>
      ${local ? `<div class="tbl-wrap" style="border:1px solid var(--line);border-radius:8px"><table><thead><tr><th>#</th><th>Hostname</th><th>Service</th><th>DNS route</th><th></th></tr></thead><tbody>
        ${ing.map((r, i) => {
          const dr = routes[r.hostname];
          const canFix = dr && ["missing", "not_proxied", "other_tunnel"].includes(dr.status);
          return `<tr class="${r.hostname ? "" : "dim"}"><td class="sub">${i + 1}</td><td class="mono">${r.hostname ? esc(r.hostname) : "<i>catch-all</i>"}${r.path ? `<div class="sub">path ${esc(r.path)}</div>` : ""}</td>
            <td class="mono small">${esc(r.service)}${Object.keys(r.origin || {}).length ? `<div class="sub">${esc(Object.entries(r.origin).map(([k, v]) => k + "=" + JSON.stringify(v)).join(" "))}</div>` : ""}</td>
            <td>${!r.hostname ? "" : dr ? `${pill(dnsClass(dr.status), dr.status.replace("_", " "))} <span class="sub">${esc(dr.detail)}</span>` : t.dns?.error ? `<span class="sub">${esc(t.dns.error)}</span>` : `<span class="sub">–</span>`}</td>
            <td><div class="row" style="justify-content:flex-end;flex-wrap:nowrap">${canFix ? `<button class="btn sm op" data-act="dns" data-ref="${ref}" data-host="${esc(r.hostname)}">${dr.status === "missing" ? "Create route" : "Fix route"}</button>` : ""}
              ${r.hostname ? `<button class="btn sm ghost op" title="Remove hostname" data-act="rmhost" data-ref="${ref}" data-host="${esc(r.hostname)}" data-path="${esc(r.path || "")}" data-dns="${dr && dr.status !== "missing" && dr.status !== "other_tunnel" && dr.status !== "conflict" ? 1 : ""}">Remove</button>` : ""}</div></td></tr>`;
        }).join("") || `<tr><td colspan="5" class="empty">No ingress rules.</td></tr>`}
      </tbody></table></div>
      ${t.dns?.orphans?.length ? `<div class="small">${pill("warn", "orphan DNS")} <span class="muted">These records point at this tunnel but have no ingress rule (they'll hit the catch-all):</span> ${t.dns.orphans.map((o) => `<span class="chip">${esc(o)}</span>`).join("")}</div>` : ""}`
      : `<div class="muted small">Token-run tunnel: its public hostnames are managed in the Cloudflare Zero Trust dashboard, not in a local config.yml. You can still start/stop/restart, read logs or delete it here.</div>`}
    </div>`;
  },
  async after(changed) {
    if (!changed) return;
    try { S.inv = await api("/api/inventory"); } catch { /* ignore */ }
    refresh();
  },
  async onClick(e) {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act;
    if (act === "new") return this.newTunnel(b.dataset.node);
    if (act === "cfdel") return this.cfDelete(b.dataset);
    const ref = b.dataset.ref, [node, name] = ref.split("/").map(decodeURIComponent);
    if (act === "edit") return Editor.open("tunnel", `${node}:${name}`);
    if (act === "logs") return showLogs(`cloudflared logs · ${name}`, (_, n) => api(`/api/tunnels/${ref}/logs?lines=${n}`));
    if (act === "addhost") return this.addHost(ref, name);
    if (act === "rmhost") return this.rmHost(ref, name, b.dataset);
    if (act === "del") return this.delTunnel(ref, node, name);
    if (act === "test") {
      const w = document.createElement("div");
      w.innerHTML = `<p class="muted small" style="margin:0">Shows which ingress rule <code>cloudflared tunnel ingress rule</code> matches for a URL.</p>
        <div class="row"><input type="text" class="grow" placeholder="https://app.adproject.fun/path" data-url><button class="btn pri" data-go>Test</button></div><pre class="out hidden" data-res></pre>`;
      const go = async () => {
        const res = $("[data-res]", w); res.classList.remove("hidden", "ok", "bad"); res.textContent = "…";
        try { const r = await api(`/api/tunnels/${ref}/test`, { body: { url: $("[data-url]", w).value.trim() } }); res.textContent = r.output; res.classList.add(r.ok ? "ok" : "bad"); }
        catch (err) { res.textContent = err.message; res.classList.add("bad"); }
      };
      w.addEventListener("click", (ev) => ev.target.closest("[data-go]") && go());
      w.addEventListener("keydown", (ev) => ev.key === "Enter" && go());
      setTimeout(() => $("[data-url]", w)?.focus(), 30);
      return modal({ title: `Test ingress rule · ${name}`, body: w });
    }
    if (act === "svc") {
      const a = b.dataset.a;
      if (a !== "start") {
        const ok = await confirmBox(`${a[0].toUpperCase() + a.slice(1)} ${name}?`, `<p>${a === "stop" ? "<b>All hostnames on this tunnel go offline</b> until it is started again." : "Connections to the Cloudflare edge drop for a few seconds while cloudflared reconnects."}</p>`, a, a === "stop" ? "danger" : "pri");
        if (!ok) return;
      }
      busy(b, true);
      try { const r = await api(`/api/tunnels/${ref}/service`, { body: { action: a } }); r.ok ? toast(`${name}: ${a} OK`, "ok") : showOutput(`${a} failed`, r); }
      catch (err) { toast(err.message, "bad"); } finally { busy(b, false); refresh(); }
    }
    if (act === "dns") {
      const host = b.dataset.host;
      const ok = await confirmBox("Route DNS to this tunnel?", `<p>Creates or updates a <b>proxied CNAME</b> <code>${esc(host)}</code> → <code>&lt;tunnel-id&gt;.cfargotunnel.com</code> in Cloudflare.</p><p class="muted small">Needs a token with Zone · DNS · Edit.</p>`, "Route DNS");
      if (!ok) return;
      busy(b, true);
      try { const r = await api(`/api/tunnels/${ref}/dns`, { body: { hostname: host } }); toast(r.output, "ok"); }
      catch (err) { toast(err.message, "bad"); } finally { busy(b, false); refresh(); }
    }
  },

  async newTunnel(node) {
    const inv = S.inv.cloudflared.find((x) => x.name === node) || {};
    const accs = S.inv.cf_accounts;
    if (!accs.length) return toast("Add a Cloudflare account (with an API token) in Settings → Cloudflare first.", "bad");
    const changed = await taskModal({
      title: `New tunnel on ${node}`, submit: "Create tunnel", size: "",
      html: `<div class="two"><label>Tunnel name<input name="name" type="text" placeholder="sw-tunnel" pattern="[a-z0-9][a-z0-9\\-]{0,38}[a-z0-9]" required autocomplete="off"><div class="hint">lowercase, digits, dashes</div></label>
        <label>Cloudflare account<select name="account">${accs.map((a) => `<option>${esc(a)}</option>`).join("")}</select></label></div>
        <div class="sep">First hostname <span class="muted">(optional — you can add more later)</span></div>
        <div class="two"><label>Public hostname<input name="hostname" type="text" placeholder="app.selatwave.com" autocomplete="off"></label>
        <label>Service (origin)<input name="service" type="text" placeholder="http://10.10.10.20:80" autocomplete="off">${SERVICE_HINT}</label></div>
        <label class="check"><input type="checkbox" name="route_dns" checked> Create the DNS record (proxied CNAME → tunnel)</label>
        <div class="note">Creates the tunnel in Cloudflare, writes <code>${esc(inv.base_dir || "/root/.cloudflared")}/&lt;name&gt;/</code> (credentials + config.yml) and
          <code>cloudflared-&lt;name&gt;.service</code> on ${esc(node)}, then enables and starts it. If anything fails it is all undone.<br>Token needs <b>Cloudflare Tunnel: Edit</b> (and <b>DNS: Edit</b> for the record).</div>`,
      run: (fd) => {
        if (fd.hostname && !fd.service) throw new Error("enter the service for the hostname");
        return api(`/api/tunnels/${encodeURIComponent(node)}/create`, { body: fd });
      },
    });
    this.after(changed);
  },

  async addHost(ref, name) {
    const changed = await taskModal({
      title: `Add hostname · ${name}`, submit: "Add & apply", size: "",
      html: `<div class="two"><label>Public hostname<input name="hostname" type="text" placeholder="erp.selatwave.com" required autocomplete="off"></label>
        <label>Service (origin)<input name="service" type="text" placeholder="http://10.10.10.20:80" required autocomplete="off">${SERVICE_HINT}</label></div>
        <details><summary>Options</summary><div class="two" style="margin-top:10px">
          <label>Path (regex, optional)<input name="path" type="text" placeholder="^/api/.*" autocomplete="off"></label>
          <label>HTTP Host header (optional)<input name="http_host_header" type="text" placeholder="app.internal.lan" autocomplete="off"></label></div>
          <label class="check"><input type="checkbox" name="no_tls_verify"> No TLS verify (origin uses a self-signed certificate)</label></details>
        <label class="check"><input type="checkbox" name="route_dns" checked> Create the DNS record (proxied CNAME → this tunnel)</label>
        <div class="note">Inserted before the catch-all rule. Validated with <code>cloudflared ingress validate</code>, config backed up, tunnel restarted (a few seconds of reconnect), auto-rollback if it doesn't come back.</div>`,
      run: (fd) => api(`/api/tunnels/${ref}/hostname`, { body: { ...fd, action: "add" } }),
    });
    this.after(changed);
  },

  async rmHost(ref, name, ds) {
    const changed = await taskModal({
      title: `Remove ${ds.host}?`, submit: "Remove & apply", cls: "danger",
      html: `<p style="margin:0">Removes the ingress rule <code>${esc(ds.host)}${ds.path ? " " + esc(ds.path) : ""}</code> from <b>${esc(name)}</b> and restarts the tunnel. Requests for it will hit the catch-all.</p>
        <label class="check"><input type="checkbox" name="delete_dns" ${ds.dns ? "checked" : ""}> Also delete its DNS record (only if it points at this tunnel)</label>`,
      run: (fd) => api(`/api/tunnels/${ref}/hostname`, { body: { action: "remove", hostname: ds.host, path: ds.path, delete_dns: fd.delete_dns } }),
    });
    this.after(changed);
  },

  async delTunnel(ref, node, name) {
    const { t } = this.find(node, name);
    const hosts = [...new Set([...(t?.dns?.routes || []).filter((r) => ["ok", "not_proxied"].includes(r.status)).map((r) => r.hostname), ...(t?.dns?.orphans || [])])];
    const changed = await taskModal({
      title: `Delete tunnel ${name}`, submit: "Delete tunnel", cls: "danger", size: "",
      html: `<p style="margin:0"><b>Every hostname on this tunnel goes offline.</b> On ${esc(node)} the service <code>${esc(t?.unit || "")}</code> is stopped and disabled, and its files
          (config, credentials, backups${t && !t.unit.includes("@") ? ", unit file" : ""}) are moved to <code>.gwc-archive/</code> — nothing is erased locally.</p>
        <label class="check"><input type="checkbox" name="delete_cf" ${t?.edge ? "checked" : "disabled"}> Delete the tunnel in Cloudflare${t?.edge ? ` (${esc(t.cf_account)})` : " — not found in a configured account"}</label>
        <label class="check"><input type="checkbox" name="delete_dns" ${hosts.length ? "checked" : ""} ${t?.edge ? "" : "disabled"}> Delete DNS records pointing at it${hosts.length ? `: ${hosts.map((h) => `<span class="chip">${esc(h)}</span>`).join("")}` : " (none found)"}</label>
        <label><span>Type <b class="mono">${esc(name)}</b> to confirm</span><input name="confirm" type="text" autocomplete="off" required></label>`,
      run: (fd) => {
        if (fd.confirm !== name) throw new Error(`type ${name} exactly to confirm`);
        return api(`/api/tunnels/${ref}/delete`, { body: fd });
      },
    });
    this.after(changed);
  },

  async cfDelete(ds) {
    const changed = await taskModal({
      title: `Delete ${ds.name} in Cloudflare`, submit: "Delete", cls: "danger",
      html: `<p style="margin:0">Deletes tunnel <code>${esc(ds.name)}</code> (${esc(ds.id)}) from account <b>${esc(ds.acc)}</b>. It has no live connections.</p>
        <label class="check"><input type="checkbox" name="delete_dns" checked> Also delete DNS records pointing at it</label>
        <label><span>Type <b class="mono">${esc(ds.name)}</b> to confirm</span><input name="confirm" type="text" autocomplete="off" required></label>`,
      run: (fd) => {
        if (fd.confirm !== ds.name) throw new Error(`type ${ds.name} exactly to confirm`);
        return api(`/api/cf/${encodeURIComponent(ds.acc)}/tunnels/${encodeURIComponent(ds.id)}/delete`, { body: fd });
      },
    });
    this.after(changed);
  },
};

