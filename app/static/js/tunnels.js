/* Gateway Console web UI — CF Tunnels page: every cloudflared tunnel (auto-discovered) in a filterable
 * list with a detail panel (hostnames with their full route through HAProxy, DNS fixes, site status,
 * edge connections), a Hostnames tab showing every public hostname end to end, create/delete tunnels,
 * add/remove hostnames, orphan DNS clean-up, and "Edit config" which opens the side-panel editor. */
"use strict";

const SERVICE_HINT = `<div class="hint">e.g. <code>http://10.10.10.20:80</code> · <code>https://10.10.10.20:443</code> · <code>tcp://10.10.10.20:25565</code> · <code>ssh://10.10.10.20:22</code></div>`;

PAGES.tunnels = {
  every: 15,
  view: "tunnels",                 // tunnels | hosts
  sel: null,                       // "node/tunnel" shown in the detail panel
  ptab: "hosts",                   // hosts | conns | details
  q: "", attention: false, fnode: "", facc: "",
  mount(v, params) {
    if (params[0] === "hostnames") this.view = "hosts";
    setHeader("CF Tunnels", "cloudflared on your nodes · Cloudflare edge · public hostnames and DNS");
    v.innerHTML = `<div id="tunAcc"></div><div class="kpis" id="tunKpi"></div>
      <div class="ptab2" id="tunTabs"><button data-v="tunnels">Tunnels</button><button data-v="hosts">Hostnames <em id="tunHostCount"></em></button>
        <span class="grow" style="flex:1"></span><span id="tunNew" style="align-self:center"></span></div>
      <div class="filters"><input type="search" id="tunQ" placeholder="Search tunnel, hostname or backend…" value="${esc(this.q)}">
        <span class="segs" id="tunAtt"><button data-a="0">All</button><button data-a="1">Needs attention <em id="tunAttN"></em></button></span>
        <select id="tunNode"><option value="">Node: all</option></select><select id="tunAccSel"><option value="">Account: all</option></select>
        <span class="grow"></span><button class="btn sm hidden" id="tunCsv">Export CSV</button></div>
      <div id="tunMain"><div class="panel"><div class="empty">Loading…</div></div></div>
      <div id="tunUnmanaged"></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
    $("#tunQ").addEventListener("input", (e) => { this.q = e.target.value.trim().toLowerCase(); this.draw(); });
    $("#tunNode").addEventListener("change", (e) => { this.fnode = e.target.value; this.draw(); });
    $("#tunAccSel").addEventListener("change", (e) => { this.facc = e.target.value; this.draw(); });
  },

  async load() {
    const d = await api("/api/tunnels");
    if (S.page !== "tunnels" || $(".menu")) return;      // don't redraw under an open ⋯ menu
    S.cache.tun = d;
    const accErr = Object.entries(d.accounts).filter(([, a]) => a.error);
    $("#tunAcc").innerHTML = accErr.length ? `<div class="panel"><div class="bd">${accErr.map(([n, a]) => `<div>${pill("warn", "CF API")} <b>${esc(n)}</b> <span class="muted">${esc(a.error)}</span></div>`).join("")}</div></div>` : "";
    const nodes = d.nodes.map((n) => n.node);
    $("#tunNew").innerHTML = nodes.length === 1 ? `<button class="btn sm pri op" data-act="new" data-node="${esc(nodes[0])}">+ New tunnel</button>`
      : nodes.length ? `<span class="kebab"><button class="btn sm pri op" data-act="newpick" style="color:#fff">+ New tunnel ▾</button></span>` : "";
    const fill = (sel, label, vals, cur) => { sel.innerHTML = `<option value="">${label}: all</option>` + vals.map((x) => `<option ${x === cur ? "selected" : ""}>${esc(x)}</option>`).join(""); };
    fill($("#tunNode"), "Node", nodes, this.fnode);
    fill($("#tunAccSel"), "Account", [...new Set(this.all().map((x) => x.t.cf_account).filter(Boolean))], this.facc);
    this.kpis(d);
    this.draw();
    this.unmanaged(d);
  },

  /** every tunnel with its node, plus derived flags */
  all() {
    const d = S.cache.tun;
    if (!d) return [];
    return d.nodes.flatMap((n) => (n.tunnels || []).map((t) => {
      const routes = Object.fromEntries((t.dns?.routes || []).map((r) => [r.hostname, r]));
      const hosts = t.config.ingress.filter((r) => r.hostname);
      const dnsBad = hosts.filter((r) => routes[r.hostname] && routes[r.hostname].status !== "ok").length;
      const down = hosts.filter((r) => ["down", "failing"].includes(r.site?.status)).length;
      const svcOk = t.service.active === "active", edgeOk = !t.edge || t.edge.status === "healthy";
      const health = !svcOk || (t.edge && ["down", "inactive"].includes(t.edge.status)) || t.config.error ? "crit" : (!edgeOk || dnsBad || down) ? "warn" : "ok";
      return { n, t, key: `${n.node}/${t.name}`, routes, hosts, dnsBad, down, health, attention: health !== "ok" || !!t.dns?.orphans?.length };
    }));
  },

  hostsFlat() {
    return this.all().flatMap((x) => x.hosts.map((r) => ({ x, r, dr: x.routes[r.hostname] })));
  },

  kpis(d) {
    const all = this.all(), flat = this.hostsFlat();
    const ok = all.filter((x) => x.t.service.active === "active" && (!x.t.edge || x.t.edge.status === "healthy")).length;
    const conns = all.flatMap((x) => x.t.edge?.connections || []);
    const colos = [...new Set(conns.map((c) => c.colo))];
    const dnsBad = flat.filter((h) => h.dr && h.dr.status !== "ok").length;
    const down = flat.filter((h) => h.r.site?.status === "down").length;
    const today = all.reduce((a, x) => a + (x.t.requests_today || 0), 0);
    const um = d.unmanaged || [];
    const live = um.filter((t) => t.connections.length).length;
    const tile = (cls, l, v, sub) => `<div class="kpi ${cls}"><div class="l">${l}</div><div class="v">${v}</div><div class="d">${sub}</div>${cls ? `<div class="bar" style="width:100%"></div>` : ""}</div>`;
    const nodes = d.nodes.length, ver = d.nodes.find((n) => n.version)?.version || "";
    $("#tunKpi").innerHTML =
      tile(ok < all.length ? "crit" : "", "Tunnels healthy", `${ok} <small>/ ${all.length}</small>`, `on ${nodes} node${nodes === 1 ? "" : "s"}${ver ? " · " + esc(ver.replace(/^cloudflared version /, "").split(" ")[0]) : ""}`) +
      tile("", "Edge connections", conns.length, colos.length ? `${esc(colos.join(" · "))} — normal is 4 per tunnel` : "none") +
      tile(dnsBad || down ? "warn" : "", "Public hostnames", flat.length, dnsBad || down ? `<span class="issue">${dnsBad ? `${dnsBad} DNS issue${dnsBad > 1 ? "s" : ""}` : ""}${dnsBad && down ? " · " : ""}${down ? `${down} site${down > 1 ? "s" : ""} down` : ""}</span>` : "DNS and sites OK") +
      tile("", "Requests today", fmt.k(today), "through all tunnels (Cloudflare)") +
      tile("", "Elsewhere in Cloudflare", um.length, um.length ? `${live} running on another server · ${um.length - live} idle` : "every tunnel is managed here");
    $("#tunHostCount").textContent = `(${flat.length})`;
  },

  match(x) {
    if (this.fnode && x.n.node !== this.fnode) return false;
    if (this.facc && x.t.cf_account !== this.facc) return false;
    if (this.attention && !x.attention) return false;
    if (!this.q) return true;
    const hay = [x.t.name, x.t.unit, x.n.node, x.t.cf_account, ...x.hosts.flatMap((r) => [r.hostname, r.service, r.route?.backend, r.route?.frontend])].join(" ").toLowerCase();
    return hay.includes(this.q);
  },

  draw() {
    if (!S.cache.tun) return;
    $$("#tunTabs button").forEach((b) => b.classList.toggle("on", b.dataset.v === this.view));
    $$("#tunAtt button").forEach((b) => b.classList.toggle("on", (b.dataset.a === "1") === this.attention));
    $("#tunCsv").classList.toggle("hidden", this.view !== "hosts");
    const d = S.cache.tun;
    const bad = d.nodes.filter((n) => n.error);
    const errs = bad.map((n) => `<div class="panel"><div class="hd"><h2>${esc(n.node)}</h2>${pill("crit", "unreachable")}</div><div class="bd muted">${esc(n.error)}</div></div>`).join("");
    if (!d.nodes.length) {
      $("#tunMain").innerHTML = `<div class="panel"><div class="empty">No cloudflared nodes yet.${S.role === "superadmin" ? ` <a href="#/settings/nodes">Add one in Settings → Nodes</a>.` : ""}</div></div>`;
      return;
    }
    if (this.view === "hosts") {
      const rows = this.hostsFlat().filter(({ x, r, dr }) => {
        if (this.fnode && x.n.node !== this.fnode) return false;
        if (this.facc && x.t.cf_account !== this.facc) return false;
        if (this.attention && !((dr && dr.status !== "ok") || ["down", "failing"].includes(r.site?.status))) return false;
        return !this.q || [r.hostname, x.t.name, r.service, r.route?.backend, r.route?.frontend].join(" ").toLowerCase().includes(this.q);
      });
      $("#tunAttN").textContent = `(${this.hostsFlat().filter(({ r, dr }) => (dr && dr.status !== "ok") || ["down", "failing"].includes(r.site?.status)).length})`;
      $("#tunMain").innerHTML = errs + `<div class="panel"><div class="hd"><h2>Every public hostname, end to end</h2><span class="meta">Cloudflare DNS → tunnel → HAProxy → servers · with live status from Monitoring</span></div>
        <div class="bd flush tbl-wrap">${rows.length ? `<table><thead><tr><th>Hostname</th><th>DNS</th><th>Tunnel</th><th>cloudflared sends to</th><th>HAProxy</th><th>Servers</th><th>Site</th><th class="num">Today</th><th></th></tr></thead><tbody>
        ${rows.map(({ x, r, dr }) => {
          const rt = r.route || {};
          return `<tr><td><b class="mono">${esc(r.hostname)}</b>${r.path ? `<div class="sub">path ${esc(r.path)}</div>` : ""}</td>
            <td>${this.dnsPill(x, dr)}</td><td>${esc(x.t.name)}</td><td class="mono small">${esc(r.service)}</td>
            <td>${rt.frontend ? `${esc(rt.frontend)} → <b>${esc(rt.backend || "?")}</b>` : `<span class="muted">${rt.kind === "other" ? "—" : "not through HAProxy"}</span>`}</td>
            <td>${rt.total ? pill(rt.up === rt.total ? "ok" : rt.up ? "warn" : "crit", `${rt.up} / ${rt.total} up`) : `<span class="muted">—</span>`}</td>
            <td>${this.sitePill(r.site)}</td><td class="num">${r.today ? fmt.k(r.today) : `<span class="muted">0</span>`}</td>
            <td>${this.fixBtn(x, dr) || this.moreBtn(x, r)}</td></tr>`;
        }).join("")}</tbody></table>` : `<div class="empty">No hostnames${this.q || this.attention ? " match" : " yet"}.</div>`}</div></div>`;
      return;
    }
    const list = this.all().filter((x) => this.match(x));
    $("#tunAttN").textContent = `(${this.all().filter((x) => x.attention).length})`;
    if (!list.find((x) => x.key === this.sel)) this.sel = (list.find((x) => x.attention) || list[0])?.key || null;
    const cur = list.find((x) => x.key === this.sel);
    $("#tunMain").innerHTML = errs + `<div class="split ${cur ? "" : "nodetail"}"><div class="panel"><div class="bd flush tbl-wrap">${list.length ? `<table><thead><tr><th>Tunnel</th><th>Node</th><th>Edge</th><th>Hostnames</th><th class="num">Today</th><th>Up</th><th></th></tr></thead><tbody>
      ${list.map((x) => {
        const t = x.t, conns = t.edge?.connections || [];
        return `<tr class="click ${x.key === this.sel ? "sel" : ""}" data-sel="${esc(x.key)}"><td><span class="dot ${x.health}"></span><b>${esc(t.name)}</b>
            <div class="sub" style="margin-left:17px">${esc(t.cf_account || "no account")} · ${esc(t.remote ? "token-run" : t.unit)}</div></td>
          <td style="white-space:nowrap">${esc(x.n.node)}</td>
          <td>${conns.map((c) => `<span class="colo" title="${esc(c.origin_ip + " · v" + c.version)}">${esc(c.colo)}</span>`).join("") || `<span class="muted">${t.edge ? "none" : "—"}</span>`}</td>
          <td>${t.remote ? `<span class="sub">Zero Trust</span>` : x.hosts.length}${x.dnsBad ? ` <span class="issue">· ${x.dnsBad} DNS</span>` : ""}${x.down ? ` <span class="issue" style="color:var(--crit)">· ${x.down} down</span>` : ""}</td>
          <td class="num" style="white-space:nowrap"><span style="margin-right:8px">${fmt.k(t.requests_today || 0)}</span>${Charts.spark(t.requests_week, { w: 70, h: 20 })}</td>
          <td>${t.service.active === "active" ? this.upFor(t.service.since) : pill(svcClass(t.service.active), t.service.active)}</td>
          <td><span class="kebab"><button data-act="tmenu" data-ref="${this.ref(x)}">⋯</button></span></td></tr>`;
      }).join("")}</tbody></table>` : `<div class="empty">${this.q || this.attention || this.fnode || this.facc ? "No tunnels match." : "No cloudflared services found yet."}</div>`}</div></div>
      ${cur ? this.panel(cur) : ""}</div>`;
  },

  ref(x) { return `${encodeURIComponent(x.n.node)}/${encodeURIComponent(x.t.name)}`; },
  upFor(since) {
    const m = String(since || "").match(/(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})/);
    if (!m) return "–";
    return fmt.dur(Math.max(0, (Date.now() - new Date(`${m[1]}T${m[2]}`).getTime()) / 1000)).split(" ")[0];
  },
  dnsPill(x, dr) {
    if (!dr) return x.t.dns?.error ? `<span class="sub" title="${esc(x.t.dns.error)}">unknown</span>` : `<span class="muted">—</span>`;
    return `<span title="${esc(dr.detail)}">${pill(dnsClass(dr.status), dr.status === "other_tunnel" ? "other tunnel" : dr.status.replace("_", " "))}</span>`;
  },
  sitePill(s, short) {
    if (!s || !s.status) return `<span class="pill mute">—</span>`;
    const cls = { up: "ok", slow: "warn", failing: "warn", down: "crit" }[s.status] || "mute";
    const txt = s.status === "up" ? `${s.code}${s.ms && !short ? ` · ${s.ms} ms` : ""}` : s.status === "slow" ? (short ? "slow" : `slow · ${fmt.ms(s.ms)}`) : s.code ? `${s.code}` : s.status;
    return `<span title="${esc(s.status + (s.ms ? ` · ${fmt.ms(s.ms)}` : ""))}">${pill(cls, txt)}</span>`;
  },
  fixBtn(x, dr) {
    if (!dr || !["missing", "not_proxied", "other_tunnel"].includes(dr.status) || x.t.remote) return "";
    return `<button class="btn xs ${dr.status === "missing" ? "pri" : ""} op" data-act="dns" data-ref="${this.ref(x)}" data-host="${esc(dr.hostname)}">${dr.status === "missing" ? "Create route" : "Fix route"}</button>`;
  },
  moreBtn(x, r) {
    return `<span class="kebab"><button data-act="hmenu" data-ref="${this.ref(x)}" data-host="${esc(r.hostname)}" data-path="${esc(r.path || "")}">⋯</button></span>`;
  },
  routeLine(r) {
    const rt = r.route || {};
    if (rt.frontend) return `${esc(r.service)}<span class="arr">→</span>HAProxy <b>${esc(rt.frontend)}</b><span class="arr">→</span><b>${esc(rt.backend || "?")}</b>${rt.how === "default" ? " (default)" : ""}${rt.total ? ` (${rt.up}/${rt.total} server${rt.total > 1 ? "s" : ""} up)` : ""}`;
    if (rt.kind === "other") return esc(r.service);
    return `${esc(r.service)}<span class="arr">→</span>direct, not through HAProxy`;
  },

  panel(x) {
    const t = x.t, e = t.edge, ref = this.ref(x), local = !t.remote;
    const conns = e?.connections || [];
    const svc = t.service.active === "active";
    let body = "";
    if (this.ptab === "hosts") {
      if (!local) body = `<div class="muted small">Token-run tunnel: its public hostnames are managed in the Cloudflare Zero Trust dashboard, not in a local config.yml. You can still start/stop/restart, read logs or delete it here.</div>`;
      else body = `<table style="font-size:12.5px"><thead><tr><th>Hostname → where it goes</th><th>DNS</th><th>Site</th><th></th></tr></thead><tbody>
        ${t.config.ingress.map((r) => {
          const dr = x.routes[r.hostname];
          if (!r.hostname) return `<tr class="dim"><td><i class="muted">everything else</i><div class="route">${esc(r.service)}</div></td><td></td><td></td><td></td></tr>`;
          return `<tr><td><b class="mono">${esc(r.hostname)}</b>${r.path ? ` <span class="sub">path ${esc(r.path)}</span>` : ""}<div class="route">${this.routeLine(r)}</div></td>
            <td><div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">${this.dnsPill(x, dr)} ${this.fixBtn(x, dr)}</div></td><td>${this.sitePill(r.site, true)}</td><td>${this.moreBtn(x, r)}</td></tr>`;
        }).join("") || `<tr><td colspan="4" class="empty">No ingress rules.</td></tr>`}</tbody></table>
        ${(t.dns?.orphans || []).map((o) => `<div class="small">${pill("warn", "orphan DNS")} <span class="muted"><b>${esc(o)}</b> points here but has no rule — visitors get the catch-all.</span>
          <button class="btn xs op" data-act="orphdel" data-ref="${ref}" data-host="${esc(o)}">Delete record</button> <button class="btn xs op" data-act="orphadd" data-ref="${ref}" data-host="${esc(o)}">Add a rule</button></div>`).join("")}`;
      body += `<div class="mcards"><div><div class="l">Account</div><div class="v">${esc(t.cf_account || "—")}</div></div>
        <div><div class="l">Connections</div><div class="v">${conns.length} · ${esc([...new Set(conns.map((c) => c.colo))].join(" ") || "none")}</div></div>
        <div><div class="l">Running since</div><div class="v" title="${esc(t.service.since)}">${esc((t.service.since || "–").replace(/^\w{3} /, "").replace(/:\d\d [+-]\d+$/, "").replace(/ [A-Z]{2,5}$/, ""))}</div></div></div>`;
    } else if (this.ptab === "conns") {
      body = conns.length ? `<table style="font-size:12.5px"><thead><tr><th>Edge</th><th>From</th><th>cloudflared</th><th>Opened</th></tr></thead><tbody>
        ${conns.map((c) => `<tr><td><span class="colo">${esc(c.colo)}</span></td><td class="mono small">${esc(c.origin_ip)}</td><td class="mono small">${esc(c.version)}</td><td class="small">${esc(fmt.ago(c.opened_at))}</td></tr>`).join("")}</tbody></table>`
        : `<div class="empty">${e ? "No live connections to the Cloudflare edge." : esc(t.edge_error || "Tunnel not found in a configured Cloudflare account.")}</div>`;
    } else {
      body = `<dl class="kv"><dt>Tunnel ID</dt><dd class="mono">${esc((e && e.id) || t.config.tunnel || "–")}</dd>
        <dt>Account</dt><dd>${t.cf_account ? esc(t.cf_account) + (t.cf_account_auto ? ` <span class="sub">(auto-matched)</span>` : "") : `<span class="muted">not found in configured accounts</span>`}</dd>
        <dt>Service</dt><dd class="mono">${esc(t.unit)} on ${esc(x.n.node)}</dd>
        ${local ? `<dt>Config</dt><dd class="mono">${esc(t.config_path)}</dd>` : ""}
        <dt>Running since</dt><dd>${esc(t.service.since || "–")}${t.service.restarts ? ` · ${t.service.restarts} restarts` : ""}</dd>
        ${t.ready_connections != null ? `<dt>Ready conns</dt><dd>${t.ready_connections} (metrics)</dd>` : ""}
        <dt>Edge status</dt><dd>${e ? pill(edgeClass(e.status), e.status) : "–"}</dd>
        ${t.config.error ? `<dt>Config</dt><dd style="color:var(--crit)">${esc(t.config.error)}</dd>` : ""}</dl>`;
    }
    return `<div class="dpanel">
      <div class="dh"><span class="dot ${x.health}"></span><h3>${esc(t.name)}</h3>${pill(svcClass(t.service.active), svc ? "running" : t.service.active)}
        ${e ? pill(edgeClass(e.status), "edge: " + e.status) : pill("mute", t.edge_error ? "edge: API error" : "edge: not found")}${t.remote ? pill("info", "token-run") : ""}</div>
      <div class="acts2">${local ? `<button class="btn sm pri op" data-act="addhost" data-ref="${ref}">+ Hostname</button><button class="btn sm" data-act="edit" data-ref="${ref}">Edit config</button><button class="btn sm" data-act="test" data-ref="${ref}">Test a URL</button>` : ""}
        <button class="btn sm" data-act="logs" data-ref="${ref}">Logs</button><span class="grow" style="flex:1"></span>
        ${svc ? `<button class="btn sm op" data-act="svc" data-a="restart" data-ref="${ref}">Restart</button><button class="btn sm op" data-act="svc" data-a="stop" data-ref="${ref}">Stop</button>`
          : `<button class="btn sm pri op" data-act="svc" data-a="start" data-ref="${ref}">Start</button>`}
        <button class="btn sm danger op" data-act="del" data-ref="${ref}">Delete</button></div>
      <div class="ptab2">${[["hosts", `Hostnames (${x.hosts.length})`], ["conns", "Connections"], ["details", "Details"]].map(([k, l]) => `<button data-pt="${k}" class="${this.ptab === k ? "on" : ""}">${esc(l)}</button>`).join("")}</div>
      <div class="db">${body}</div></div>`;
  },

  unmanaged(d) {
    const um = d.unmanaged || [];
    const open = $("#tunUnmanaged details")?.open;
    $("#tunUnmanaged").innerHTML = um.length ? `<details class="um" ${open ? "open" : ""}><summary>Elsewhere in Cloudflare (${um.length})<span>tunnels in your accounts that no managed node runs</span></summary>
      <div class="tbl-wrap" style="border-top:1px solid var(--line)"><table><thead><tr><th>Account</th><th>Tunnel</th><th>Status</th><th>Connections</th><th>Created</th><th></th></tr></thead><tbody>
      ${um.map((t) => {
        const ips = [...new Set(t.connections.map((c) => c.origin_ip).filter(Boolean))];
        return `<tr><td>${esc(t.account)}</td><td><b>${esc(t.name)}</b><div class="sub mono">${esc(t.id)}</div></td><td>${pill(edgeClass(t.status), t.status)}</td>
          <td>${t.connections.length ? `${t.connections.length} from <span class="mono small">${esc(ips.join(", "))}</span>` : `<span class="muted">none</span>`}</td>
          <td class="small">${esc((t.created_at || "").slice(0, 10))}</td>
          <td>${t.connections.length ? `<span class="sub">running elsewhere</span>` : `<button class="btn sm danger op" data-act="cfdel" data-acc="${esc(t.account)}" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Delete</button>`}</td></tr>`;
      }).join("")}</tbody></table></div></details>` : "";
  },

  csv() {
    const rows = [["hostname", "path", "dns", "tunnel", "node", "service", "haproxy_frontend", "backend", "servers_up", "site", "requests_today"]];
    for (const { x, r, dr } of this.hostsFlat()) {
      const rt = r.route || {};
      rows.push([r.hostname, r.path || "", dr?.status || "", x.t.name, x.n.node, r.service, rt.frontend || "", rt.backend || "",
        rt.total ? `${rt.up}/${rt.total}` : "", r.site?.status || "", r.today || 0]);
    }
    const text = rows.map((r) => r.map((c) => /[",\n]/.test(String(c)) ? `"${String(c).replace(/"/g, '""')}"` : c).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
    a.download = `hostnames-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  },

  find(node, name) {
    const n = S.cache.tun.nodes.find((x) => x.node === node);
    return { n, t: n?.tunnels.find((x) => x.name === name) };
  },
  async after(changed) {
    if (!changed) return;
    try { S.inv = await api("/api/inventory"); } catch { /* ignore */ }
    refresh();
  },
  async onClick(e) {
    const vt = e.target.closest("#tunTabs button");
    if (vt) { this.view = vt.dataset.v; return this.draw(); }
    const at = e.target.closest("#tunAtt button");
    if (at) { this.attention = at.dataset.a === "1"; return this.draw(); }
    const pt = e.target.closest("[data-pt]");
    if (pt) { this.ptab = pt.dataset.pt; return this.draw(); }
    if (e.target.closest("#tunCsv")) return this.csv();
    const b = e.target.closest("[data-act]");
    const row = e.target.closest("tr[data-sel]");
    if (!b && row) { this.sel = row.dataset.sel; return this.draw(); }
    if (!b) return;
    const act = b.dataset.act;
    if (act === "newpick") {
      const node = await popMenu(b, S.cache.tun.nodes.map((n) => ({ label: `on ${n.node}`, act: n.node, op: true })));
      return node && this.newTunnel(node);
    }
    if (act === "new") return this.newTunnel(b.dataset.node);
    if (act === "tmenu") {
      const [node, name] = b.dataset.ref.split("/").map(decodeURIComponent);
      const { t } = this.find(node, name);
      const pick = await popMenu(b, [
        { label: "Open", act: "open" }, { label: "+ Hostname", act: "addhost", op: true }, { label: "Edit config", act: "edit" },
        { label: "Logs", act: "logs" }, "-", { label: t?.service.active === "active" ? "Restart" : "Start", act: t?.service.active === "active" ? "restart" : "start", op: true },
        { label: "Delete…", act: "del", cls: "danger", op: true }]);
      if (!pick) return;
      if (pick === "open") { this.sel = `${node}/${name}`; this.view = "tunnels"; return this.draw(); }
      const fake = { dataset: { act: ["restart", "start"].includes(pick) ? "svc" : pick, a: pick, ref: b.dataset.ref }, closest: (sel) => (sel === "[data-act]" ? fake : null) };
      return this.onClick({ target: fake });
    }
    if (act === "hmenu") {
      const host = b.dataset.host, [node, name] = b.dataset.ref.split("/").map(decodeURIComponent);
      const { t } = this.find(node, name);
      const r = t?.config.ingress.find((i) => i.hostname === host && (i.path || "") === b.dataset.path) || {};
      const rt = r.route || {};
      const pick = await popMenu(b, [
        { label: "Open the site ↗", act: "open" },
        ...(rt.backend ? [{ label: `Show ${rt.backend} in HAProxy`, act: "backend" }] : []),
        { label: "Test this hostname", act: "test" }, { label: "Monitoring and check history", act: "mon" }, { label: "Traffic", act: "traffic" },
        "-", { label: "Change where it goes (edit config)", act: "edit" },
        { label: "Remove hostname…", act: "rmhost", cls: "danger", op: true }]);
      if (pick === "open") window.open(`https://${host}/`, "_blank", "noopener");
      if (pick === "backend") location.hash = `#/haproxy/${encodeURIComponent(rt.hp_node)}`;
      if (pick === "mon") location.hash = "#/monitoring";
      if (pick === "traffic") location.hash = "#/traffic";
      if (pick === "edit") Editor.open("tunnel", `${node}:${name}`);
      if (pick === "test") return this.testUrl(b.dataset.ref, name, `https://${host}/`);
      if (pick === "rmhost") {
        const dr = Object.fromEntries((t?.dns?.routes || []).map((x) => [x.hostname, x]))[host];
        return this.rmHost(b.dataset.ref, name, { host, path: b.dataset.path, dns: dr && !["missing", "other_tunnel", "conflict"].includes(dr.status) ? "1" : "" });
      }
      return;
    }
    if (act === "orphdel") {
      const ref = b.dataset.ref, host = b.dataset.host;
      if (!(await confirmBox(`Delete DNS record ${host}?`, `<p>Deletes the CNAME <code>${esc(host)}</code> that points at this tunnel in Cloudflare. No ingress rule serves it today.</p>`, "Delete record", "danger"))) return;
      busy(b, true);
      try { const r = await api(`/api/tunnels/${ref}/dns/delete`, { body: { hostname: host } }); toast(r.output, "ok"); }
      catch (err) { toast(err.message, "bad"); } finally { busy(b, false); refresh(); }
      return;
    }
    if (act === "orphadd") return this.addHost(b.dataset.ref, decodeURIComponent(b.dataset.ref.split("/")[1]), b.dataset.host);
    if (act === "cfdel") return this.cfDelete(b.dataset);
    const ref = b.dataset.ref, [node, name] = ref.split("/").map(decodeURIComponent);
    if (act === "edit") return Editor.open("tunnel", `${node}:${name}`);
    if (act === "logs") return showLogs(`cloudflared logs · ${name}`, (_, n) => api(`/api/tunnels/${ref}/logs?lines=${n}`));
    if (act === "addhost") return this.addHost(ref, name);
    if (act === "rmhost") return this.rmHost(ref, name, b.dataset);
    if (act === "del") return this.delTunnel(ref, node, name);
    if (act === "test") return this.testUrl(ref, name, "");
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

  testUrl(ref, name, url) {
    const w = document.createElement("div");
    w.innerHTML = `<p class="muted small" style="margin:0">Shows which ingress rule <code>cloudflared tunnel ingress rule</code> matches for a URL.</p>
      <div class="row"><input type="text" class="grow" placeholder="https://app.adproject.fun/path" data-url value="${esc(url)}"><button class="btn pri" data-go>Test</button></div><pre class="out hidden" data-res></pre>`;
    const go = async () => {
      const res = $("[data-res]", w); res.classList.remove("hidden", "ok", "bad"); res.textContent = "…";
      try { const r = await api(`/api/tunnels/${ref}/test`, { body: { url: $("[data-url]", w).value.trim() } }); res.textContent = r.output; res.classList.add(r.ok ? "ok" : "bad"); }
      catch (err) { res.textContent = err.message; res.classList.add("bad"); }
    };
    w.addEventListener("click", (ev) => ev.target.closest("[data-go]") && go());
    w.addEventListener("keydown", (ev) => ev.key === "Enter" && go());
    setTimeout(() => { $("[data-url]", w)?.focus(); if (url) go(); }, 30);
    return modal({ title: `Test a URL · ${name}`, body: w });
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

  async addHost(ref, name, preset = "") {
    const changed = await taskModal({
      title: `Add hostname · ${name}`, submit: "Add & apply", size: "",
      html: `<div class="two"><label>Public hostname<input name="hostname" type="text" placeholder="erp.selatwave.com" value="${esc(preset)}" required autocomplete="off"></label>
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

