/* Gateway Console web UI — Overview page: KPIs, active alerts, HAProxy node cards and tunnel cards. */
"use strict";

PAGES.overview = {
  every: 10,
  mount(v) {
    setHeader("Overview", "All gateways at a glance");
    v.innerHTML = `<div class="kpis" id="kpis"></div>
      <div class="panel"><div class="hd"><h2>Active alerts</h2><span class="meta" id="alertMeta"></span><div class="acts"><a class="btn sm" href="#/alerts">All alerts</a></div></div><div class="bd flush" id="alerts"><div class="empty">Loading…</div></div></div>
      <div class="grid2">
        <div class="panel"><div class="hd"><h2>HAProxy nodes</h2><div class="acts"><a class="btn sm" href="#/haproxy">Open</a></div></div><div class="bd"><div class="cards" id="hpCards"></div></div></div>
        <div class="panel"><div class="hd"><h2>Cloudflare tunnels</h2><div class="acts"><a class="btn sm" href="#/tunnels">Open</a></div></div><div class="bd"><div class="cards" id="tunCards"></div></div></div>
      </div>`;
  },
  async load() {
    const d = await api("/api/overview");
    if (S.page !== "overview") return;
    const k = d.kpi;
    const tile = (l, v, tot, cls) => `<div class="kpi ${cls}"><div class="l">${l}</div><div class="v">${v}${tot != null ? ` <small>/ ${tot}</small>` : ""}</div>
      <div class="bar" style="width:${tot ? Math.round((v / tot) * 100) : 100}%"></div></div>`;
    const lvl = (a, b) => (a === b ? "" : a === 0 && b ? "crit" : "warn");
    const live = d.alerts.filter((a) => !a.muted);
    const crit = live.filter((a) => a.sev === "crit" && !a.acked_by).length;
    $("#kpis").innerHTML =
      tile("HAProxy nodes up", k.haproxy_up, k.haproxy_total, lvl(k.haproxy_up, k.haproxy_total)) +
      tile("Backend servers up", k.servers_up, k.servers_total, lvl(k.servers_up, k.servers_total)) +
      tile("Tunnels healthy", k.tunnels_ok, k.tunnels_total, lvl(k.tunnels_ok, k.tunnels_total)) +
      tile("Current connections", fmt.n(k.conns), null, "") +
      `<a href="#/alerts" class="kpi ${crit ? "crit" : live.length ? "warn" : ""}"><div class="l">Open alerts</div><div class="v">${live.length}${crit ? ` <small>${crit} critical</small>` : ""}</div><div class="bar" style="width:100%"></div></a>`;
    updateBadge();
    $("#alertMeta").textContent = d.alerts.length ? `${d.alerts.length} active` : "";
    $("#alerts").innerHTML = d.alerts.length
      ? `<ul class="alerts">${d.alerts.map((a) => `<li class="${a.muted || a.acked_by ? "dim" : ""}">${pill(a.sev === "crit" ? "crit" : "warn", a.sev === "crit" ? "CRIT" : "WARN")}<span class="w">${esc(a.where)}</span>
          <span class="m">${esc(a.msg)}${a.first_seen ? ` <span class="sub">· ${fmt.ago(a.first_seen)}</span>` : ""}${a.acked_by ? ` <span class="pill info">ack ${esc(a.acked_by)}</span>` : ""}${a.muted ? ` <span class="pill mute">muted</span>` : ""}</span></li>`).join("")}</ul>`
      : `<div class="empty ok">All clear — every gateway, backend and tunnel is healthy.</div>`;

    $("#hpCards").innerHTML = d.haproxy.map((n) => {
      if (n.error) return `<div class="card"><div class="t">${esc(n.node)} ${n.site ? `<span class="tag">${esc(n.site)}</span>` : ""}<span class="r">${pill("crit", "unreachable")}</span></div><div class="muted small">${esc(n.error)}</div></div>`;
      const servers = n.backends.flatMap((b) => b.servers);
      return `<div class="card"><div class="t"><a href="#/haproxy/${encodeURIComponent(n.node)}">${esc(n.node)}</a> ${n.site ? `<span class="tag">${esc(n.site)}</span>` : ""}<span class="r">${pill(svcClass(n.service.active), n.service.active)}</span></div>
        <dl class="kv"><dt>Host</dt><dd class="mono">${esc(n.host)}</dd><dt>Version</dt><dd>${esc(n.info.Version || "–")}</dd>
        <dt>Uptime</dt><dd>${fmt.dur(n.info.Uptime_sec)}</dd><dt>Connections</dt><dd>${fmt.n(n.info.CurrConns)} / ${fmt.n(n.info.Maxconn)} · ${fmt.n(n.info.ConnRate)}/s</dd>
        <dt>Backends</dt><dd>${n.backends.length} (${n.backends.filter((b) => b.status === "DOWN").length} down)</dd></dl>
        <div class="mini" title="servers">${servers.map((s) => `<i class="${srvClass(s.status)}" title="${esc(s.backend + "/" + s.name + " " + s.status)}"></i>`).join("")}</div></div>`;
    }).join("") || `<div class="empty">No HAProxy nodes configured.</div>`;

    const tun = d.tunnels.nodes.flatMap((n) => (n.error ? [{ _err: n }] : n.tunnels.map((t) => ({ ...t, _node: n }))));
    $("#tunCards").innerHTML = tun.map((t) => {
      if (t._err) return `<div class="card"><div class="t">${esc(t._err.node)}<span class="r">${pill("crit", "unreachable")}</span></div><div class="muted small">${esc(t._err.error)}</div></div>`;
      const e = t.edge;
      const colos = e ? e.connections.map((c) => `<span class="chip">${esc(c.colo)}</span>`).join("") : "";
      const bad = (t.dns?.routes || []).filter((r) => r.status !== "ok").length;
      return `<div class="card"><div class="t">${esc(t.name)} <span class="tag">${esc(t._node.node)}</span><span class="r">${pill(svcClass(t.service.active), t.service.active)}</span></div>
        <dl class="kv"><dt>Edge</dt><dd>${e ? pill(edgeClass(e.status), e.status) : t.cf_account ? pill("mute", t.edge_error ? "API error" : "not found") : `<span class="muted">no CF account linked</span>`}</dd>
        <dt>Connections</dt><dd>${e ? e.connections.length : t.ready_connections ?? "–"}</dd>
        <dt>Hostnames</dt><dd>${t.config.ingress.filter((r) => r.hostname).length}${bad ? ` · <span style="color:var(--warn)">${bad} DNS issue(s)</span>` : ""}</dd></dl>
        ${colos ? `<div>${colos}</div>` : ""}</div>`;
    }).join("") || `<div class="empty">No tunnels configured.</div>`;
  },
};
