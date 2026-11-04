/* Gateway Console web UI — Overview page: six summary tiles (sites, servers, backend servers, tunnels,
 * requests today, alerts), what needs attention, sites with response times, today's traffic, server
 * load, and the gateways (every HAProxy backend's servers, every tunnel's edge connections). */
"use strict";

PAGES.overview = {
  every: 15,
  mount(v) {
    setHeader("Overview", "Everything at a glance");
    v.innerHTML = `<div class="kpis6" id="ovKpi"></div>
      <div class="ov3">
        <div class="scol">
          <div class="panel"><div class="hd"><h2>Needs attention</h2><span class="meta" id="ovAttMeta"></span><div class="acts"><a class="btn sm" href="#/alerts">All alerts</a></div></div>
            <div id="ovAtt"><div class="empty">Loading…</div></div></div>
          <div class="panel"><div class="hd"><h2>Traffic today</h2><span class="meta" id="ovTrMeta">requests per hour</span><div class="acts"><a class="btn sm" href="#/traffic">Open Traffic</a></div></div>
            <div class="chart" id="ovTraffic"></div></div>
          <div class="panel"><div class="hd"><h2>Gateways</h2><span class="meta">HAProxy and cloudflared</span></div><div class="gw" id="ovGw"></div></div>
        </div>
        <div class="scol">
          <div class="panel"><div class="hd"><h2>Sites</h2><span class="meta">24 h</span><div class="acts"><a class="btn sm" href="#/monitoring">Open Monitoring</a></div></div>
            <div id="ovSites"></div></div>
          <div class="panel"><div class="hd"><h2>Servers</h2><span class="meta">now</span></div><div id="ovServers"></div></div>
        </div>
      </div>`;
  },

  async load() {
    const d = await api("/api/overview");
    if (S.page !== "overview") return;
    this.kpis(d);
    this.attention(d.alerts);
    this.sites(d.sites);
    this.servers(d.servers, d.settings);
    this.traffic(d.traffic);
    this.gateways(d);
    updateBadge();
  },

  kpis(d) {
    const k = d.kpi;
    const tile = (cls, l, v, sub, pct, href) => `<${href ? `a href="${href}"` : "div"} class="kpi ${cls}"><div class="l">${l}</div><div class="v">${v}</div><div class="d">${sub}</div>
      ${pct != null ? `<div class="bar" style="width:${Math.max(0, Math.min(100, pct))}%"></div>` : ""}</${href ? "a" : "div"}>`;
    const lvl = (a, b) => (!b || a === b ? "" : a === 0 ? "crit" : "warn");
    const sites = d.sites || [];
    const up = sites.filter((s) => ["up", "slow"].includes(s.status)).length;
    const down = sites.filter((s) => s.status === "down");
    const srv = d.servers || [];
    const st = d.settings || {};
    const bad = srv.filter((s) => s.error || (s.disk ?? 0) >= st.disk_warn || (s.mem ?? 0) >= st.mem_crit);
    const conns = d.tunnels.nodes.flatMap((n) => (n.tunnels || []).flatMap((t) => t.edge?.connections || [])).length;
    const live = d.alerts.filter((a) => !a.muted);
    const crit = live.filter((a) => a.sev === "crit" && !a.acked_by).length;
    const muted = d.alerts.length - live.length, acked = live.filter((a) => a.acked_by).length;
    const tr = d.traffic || {};
    const delta = tr.yesterday ? Math.round(((tr.today - tr.yesterday) / tr.yesterday) * 100) : null;
    const issue = (s) => s.error ? `${s.name} unreachable` : (s.disk ?? 0) >= st.disk_warn ? `${s.name} disk ${Math.round(s.disk)}%` : `${s.name} memory ${Math.round(s.mem)}%`;
    $("#ovKpi").innerHTML =
      tile(down.length ? "crit" : sites.length && up < sites.length ? "warn" : "", "Sites up", sites.length ? `${up} <small>/ ${sites.length}</small>` : "–",
        down.length ? (down.length === 1 ? `${esc(down[0].host)} down` : `${down.length} down: ${esc(down.slice(0, 2).map((x) => x.host).join(", "))}${down.length > 2 ? "…" : ""}`) : sites.length ? "all answering" : "none found yet", sites.length ? (up / sites.length) * 100 : null, "#/monitoring") +
      tile(bad.length ? "warn" : "", "Servers healthy", srv.length ? `${srv.length - bad.length} <small>/ ${srv.length}</small>` : "–",
        bad.length ? esc(issue(bad[0])) : srv.length ? "disk and memory OK" : "not read yet", srv.length ? ((srv.length - bad.length) / srv.length) * 100 : null, "#/monitoring") +
      tile(lvl(k.servers_up, k.servers_total), "Backend servers up", `${k.servers_up} <small>/ ${k.servers_total}</small>`,
        `${fmt.plural(d.haproxy.reduce((a, n) => a + (n.backends || []).length, 0), "backend")} on ${fmt.plural(k.haproxy_total, "node")}`, k.servers_total ? (k.servers_up / k.servers_total) * 100 : null, "#/haproxy") +
      tile(lvl(k.tunnels_ok, k.tunnels_total), "Tunnels healthy", `${k.tunnels_ok} <small>/ ${k.tunnels_total}</small>`,
        fmt.plural(conns, "edge connection"), k.tunnels_total ? (k.tunnels_ok / k.tunnels_total) * 100 : null, "#/tunnels") +
      tile("", "Requests today", tr.today ? fmt.k(tr.today) : "–",
        delta == null ? (tr.source === "hp" ? "HAProxy frontends" : "through Cloudflare") : `<span class="${delta >= 0 ? "up" : "down"}">${delta >= 0 ? "▲" : "▼"} ${Math.abs(delta)}%</span> vs yesterday`, null, "#/traffic") +
      tile(crit ? "crit" : live.length ? "warn" : "", "Open alerts", `${live.length}${crit ? ` <small>${crit} critical</small>` : ""}`,
        `${muted} muted · ${acked} acknowledged`, live.length ? 100 : 0, "#/alerts");
  },

  attention(alerts) {
    const live = alerts.filter((a) => !a.muted).sort((a, b) => (a.sev === b.sev ? (b.first_seen || 0) - (a.first_seen || 0) : a.sev === "crit" ? -1 : 1));
    const show = live.slice(0, 8);
    $("#ovAttMeta").textContent = live.length ? `${live.length} open${alerts.length > live.length ? ` · ${alerts.length - live.length} muted` : ""}` : "";
    $("#ovAtt").innerHTML = show.length ? `<ul class="att">${show.map((a) => `<li class="${a.acked_by ? "dim" : ""}">${pill(a.sev === "crit" ? "crit" : "warn", a.sev === "crit" ? "CRIT" : "WARN")}
        <span>${esc(a.msg)}<span class="w">${esc(a.where)}</span></span>
        <span class="t">${a.acked_by ? `ack ${esc(a.acked_by)} · ` : ""}${a.first_seen ? esc(fmt.ago(a.first_seen).replace(" ago", "")) : ""}</span></li>`).join("")}</ul>
      ${live.length > show.length ? `<a class="sub" style="display:block;padding:9px 16px" href="#/alerts">${fmt.plural(live.length - show.length, "more alert")} on the Alerts page →</a>` : ""}`
      : `<div class="empty ok">All clear — every site, server, gateway and tunnel is healthy.</div>`;
  },

  sites(sites) {
    const cls = { up: "ok", slow: "warn", failing: "warn", down: "crit" };
    const color = { crit: "#ff5d6c", warn: "#ffb547" };
    $("#ovSites").innerHTML = sites.length ? `<ul class="sl">${sites.slice(0, 10).map((s) => {
      const c = cls[s.status] || "mute";
      const v = s.status === "down" || s.status === "failing" ? (s.code ?? "down") : s.kind === "tcp" ? (s.code || "open") : fmt.ms(s.ms);
      return `<li><span class="dot ${c}"></span><span class="h2">${esc(s.host)}</span><span class="v2" style="${c === "crit" ? "color:var(--crit)" : c === "warn" ? "color:var(--warn)" : ""}">${esc(String(v))}</span>
        <span>${Charts.spark(s.spark, { w: 84, h: 20, color: color[c] || "#8b90ab" })}</span></li>`;
    }).join("")}</ul>${sites.length > 10 ? `<a class="sub" style="display:block;padding:9px 16px" href="#/monitoring">${fmt.plural(sites.length - 10, "more site")} →</a>` : ""}`
      : `<div class="empty">No sites yet — hostnames from your tunnels and HAProxy rules appear here automatically.</div>`;
  },

  servers(list, st) {
    const bar = (v, warn, crit) => v == null ? "–" : `<span style="${v >= crit ? "color:var(--crit)" : v >= warn ? "color:var(--warn)" : ""}">${Math.round(v)}%</span>
      <div class="bar3 ${v >= crit ? "crit" : v >= warn ? "warn" : ""}"><i style="width:${Math.min(100, v)}%"></i></div>`;
    $("#ovServers").innerHTML = list.length ? `<ul class="srvl"><li><span class="hh">Server</span><span class="hh">CPU</span><span class="hh">Memory</span><span class="hh">Disk</span></li>
      ${list.map((s) => s.error ? `<li><b>${esc(s.name)}</b><span style="grid-column:2/-1">${pill("crit", "unreachable")}</span></li>`
        : `<li><b title="${esc(s.kind)}">${esc(s.name)}</b><span>${bar(s.cpu, 70, 100)}</span><span>${bar(s.mem, st.mem_crit - 15, st.mem_crit)}</span>
          <span title="${esc(s.disk_mount || "")}">${bar(s.disk, st.disk_warn, st.disk_crit)}</span></li>`).join("")}</ul>`
      : `<div class="empty">Server health appears here a minute after the dashboard starts.</div>`;
  },

  traffic(tr) {
    const el = $("#ovTraffic");
    const hours = tr.hours || [];
    if (!hours.length) {
      el.innerHTML = `<div class="empty">${tr.source === "cf" ? "No requests through Cloudflare yet today." : "Per-hour numbers come from Cloudflare — add a token with Analytics: Read in Settings → Cloudflare accounts."}</div>`;
      return;
    }
    const labels = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0"));
    Charts.bars(el, labels, hours, { h: 190, xFmt: (l) => l, tipFmt: (l) => `${l}:00` });
  },

  gateways(d) {
    const hp = d.haproxy.map((n) => {
      if (n.error) return `<div class="gwc"><div class="t">${esc(n.node)} <span class="tag">HAProxy</span><span class="r">${pill("crit", "unreachable")}</span></div><div class="cap2">${esc(n.error)}</div></div>`;
      const be = (n.backends || []).map((b) => {
        const up = b.servers.filter((s) => srvClass(s.status) === "ok").length;
        return `<div class="be2"><a class="n" href="#/haproxy/${encodeURIComponent(n.node)}" title="${esc(b.name)}">${esc(b.name)}</a>
          <span class="sq">${b.servers.map((s) => `<i class="${srvClass(s.status)}" title="${esc(`${s.name} · ${s.status}${s.addr ? " · " + s.addr : ""}`)}"></i>`).join("")}</span>
          <span class="cap2" style="${b.servers.length && !up ? "color:var(--crit)" : ""}">${up}/${b.servers.length}</span></div>`;
      }).join("");
      return `<div class="gwc"><div class="t"><a href="#/haproxy/${encodeURIComponent(n.node)}">${esc(n.node)}</a> <span class="tag">HAProxy</span>${n.site ? `<span class="tag">${esc(n.site)}</span>` : ""}
          <span class="r">${pill(svcClass(n.service.active), n.service.active)}</span></div>
        <div class="cap2">${esc((n.info.Version || "").split("-")[0])} · up ${fmt.dur(n.info.Uptime_sec)} · ${fmt.n(n.info.CurrConns)} / ${fmt.n(n.info.Maxconn)} connections</div>
        <div class="bes">${be || `<span class="cap2">No backends.</span>`}</div></div>`;
    });
    const cf = d.tunnels.nodes.map((n) => {
      if (n.error) return `<div class="gwc"><div class="t">${esc(n.node)} <span class="tag">cloudflared</span><span class="r">${pill("crit", "unreachable")}</span></div><div class="cap2">${esc(n.error)}</div></div>`;
      const ts = n.tunnels || [];
      const okN = ts.filter((t) => t.service.active === "active").length;
      const rows = ts.map((t) => {
        const bad = (t.dns?.routes || []).filter((r) => r.status !== "ok").length;
        const colos = (t.edge?.connections || []).map((c) => `<span class="colo">${esc(c.colo)}</span>`).join("");
        return `<div class="be2"><a class="n" href="#/tunnels" title="${esc(t.name)}">${esc(t.name)}</a><span>${t.service.active !== "active" ? pill("crit", t.service.active) : colos || `<span class="cap2">no edge connections</span>`}</span>
          <span class="cap2" style="${bad ? "color:var(--warn)" : ""}">${bad ? `${bad} DNS` : "ok"}</span></div>`;
      }).join("");
      return `<div class="gwc"><div class="t"><a href="#/tunnels">${esc(n.node)}</a> <span class="tag">cloudflared</span>${n.site ? `<span class="tag">${esc(n.site)}</span>` : ""}
          <span class="r">${pill(okN === ts.length ? "ok" : "warn", fmt.plural(ts.length, "tunnel"))}</span></div>
        <div class="cap2">${esc((n.version || "").replace(/^cloudflared version /, "").split(" ")[0])}</div>
        <div class="bes">${rows || `<span class="cap2">No tunnels.</span>`}</div></div>`;
    });
    $("#ovGw").innerHTML = [...hp, ...cf].join("") || `<div class="empty">No gateways yet.${can("superadmin") ? ` <a href="#/settings/nodes">Add one in Settings → Nodes</a>.` : ""}</div>`;
  },
};
