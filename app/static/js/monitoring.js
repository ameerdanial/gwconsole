/* Gateway Console web UI — Monitoring page: sites (public + internal checks, uptime, certificates),
 * servers (CPU load, memory, disk, watched services with Restart), and graphs over 1 h – 7 days.
 * Site details open in a modal with per-site options (path, expected status, keyword, slow limit). */
"use strict";

const SEVEN = 7 * 86400;

PAGES.monitoring = {
  every: 30,
  range: "24h",
  mount(v) {
    setHeader("Monitoring", "Sites, servers and services");
    v.innerHTML = `<div class="row" style="justify-content:flex-end;gap:10px">
        <span class="sub" id="monWhen"></span><span class="grow"></span>
        <span class="segs" id="monRange">${["1h", "6h", "24h", "7d"].map((r) => `<button data-r="${r}" class="${r === this.range ? "on" : ""}">${r === "7d" ? "7 days" : r}</button>`).join("")}</span>
        <button class="btn sm op" data-act="run">Check now</button></div>
      <div class="kpis" id="monKpi"></div>
      <div id="monErr"></div>
      <div class="panel"><div class="hd"><h2>Sites</h2><span class="meta">Found automatically from your tunnels and HAProxy rules · public = through Cloudflare, internal = straight to the origin</span>
        <div class="acts"><button class="btn sm op" data-act="addsite">+ Add a check</button></div></div>
        <div class="bd flush tbl-wrap" id="monSites"><div class="empty">Loading…</div></div></div>
      <div class="panel"><div class="hd"><h2>Servers</h2><span class="meta">Gateways and your other servers · read over SSH</span>
        ${S.role === "superadmin" ? `<div class="acts"><a class="btn sm" href="#/settings/nodes">+ Add server</a></div>` : ""}</div>
        <div class="bd flush tbl-wrap" id="monServers"></div></div>
      <div class="grid2" id="monCharts"></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
  },

  async load() {
    const d = await api("/api/monitor");
    if (S.page !== "monitoring") return;
    S.cache.mon = d;
    setHeader("Monitoring", `Sites, servers and services · checked every ${d.settings.check_every} s`);
    $("#monWhen").textContent = d.last_run ? `last round ${fmt.ago(d.last_run)}` : d.sites.length ? "" : "first checks run a few seconds after start";
    $("#monErr").innerHTML = d.error ? `<div class="panel"><div class="bd small">${pill("warn", "monitor")} <span class="muted">${esc(d.error)}</span></div></div>` : "";
    this.kpis(d);
    this.sites(d);
    this.servers(d);
    await this.charts(d);
  },

  kpis(d) {
    const k = d.kpi, c = k.cert_next;
    const tile = (cls, l, v, sub) => `<div class="kpi ${cls}"><div class="l">${l}</div><div class="v">${v}</div><div class="d">${sub}</div>${cls ? `<div class="bar" style="width:100%"></div>` : ""}</div>`;
    const sitesCls = k.down.length ? "crit" : "";
    const srvBad = k.servers_total - k.servers_ok;
    const svcBad = k.services_total - k.services_ok;
    $("#monKpi").innerHTML =
      tile(sitesCls, "Sites up", `${k.sites_up} <small>/ ${k.sites_total}</small>`, k.down.length ? `${esc(k.down.slice(0, 2).join(", "))} down` : k.sites_total ? "all answering" : "no sites found yet") +
      tile("", "Response time (public, median)", k.median_ms != null ? `${k.median_ms} <small>ms</small>` : "–", "through Cloudflare") +
      tile(srvBad ? "warn" : "", "Servers healthy", `${k.servers_ok} <small>/ ${k.servers_total}</small>`, srvBad ? "disk or memory high, or unreachable" : "disk and memory OK") +
      tile(svcBad ? "crit" : "", "Watched services", `${k.services_ok} <small>/ ${k.services_total} running</small>`, svcBad ? "a service is stopped" : k.services_total ? "all running" : "none watched yet") +
      tile(c && c.days <= 14 ? (c.days <= 3 ? "crit" : "warn") : "", "Certificates", c ? (c.days > 14 ? "all OK" : `${c.days} <small>days</small>`) : "–", c ? `next expiry in ${c.days} days · ${esc(c.where)}` : "none found");
  },

  status(s) {
    const st = s.state || {};
    return { up: ["ok", "up"], slow: ["warn", "slow"], failing: ["warn", "failing"], down: ["crit", "down"] }[st.status] || ["mute", "not checked"];
  },

  side(r, label) {
    if (!r) return `<span class="pill mute">—</span>`;
    const cls = r.ok ? (r.slow >= 3 ? "warn" : "ok") : r.fails >= 3 ? "crit" : "warn";
    return `${pill(cls, r.code ?? (r.ok ? "ok" : "down"))}<span class="ms" title="${esc(r.err || "")}">${r.ok ? fmt.ms(r.ms) : esc((r.err || "").slice(0, 34))}</span>`;
  },

  routeText(s) {
    const r = s.route || {};
    const parts = [s.kind === "tcp" ? "TCP" : "HTTP"];
    if (r.frontend) parts.push(`${r.frontend} → ${r.backend || "?"}`);
    else if (r.tunnel) parts.push(`${r.tunnel.name} → ${s.internal}`);
    else if (s.internal) parts.push(s.internal);
    return parts.join(" · ");
  },

  sites(d) {
    const rows = d.sites.filter((s) => !s.excluded);
    const order = { down: 0, failing: 1, slow: 2, up: 3 };
    rows.sort((a, b) => (order[a.state.status] ?? 4) - (order[b.state.status] ?? 4) || a.host.localeCompare(b.host));
    const excl = d.sites.length - rows.length;
    $("#monSites").innerHTML = rows.length ? `<table><thead><tr><th>Site</th><th>Public</th><th>Internal</th><th>Response time · 24 h</th>
        <th class="num">Uptime 24 h</th><th class="num">7 days</th><th>Certificate</th><th></th></tr></thead><tbody>
      ${rows.map((s) => {
        const st = s.state, [cls] = this.status(s), c = st.cert || {};
        const color = cls === "crit" ? "#ff5d6c" : cls === "warn" ? "#ffb547" : "#8b90ab";
        return `<tr class="click" data-site="${esc(s.host)}"><td><span class="dot ${cls}"></span><b>${esc(s.host)}</b><div class="sub" style="margin-left:17px">${esc(this.routeText(s))}</div></td>
          <td>${s.kind === "tcp" ? `<span class="pill mute">—</span><span class="ms">TCP: internal only</span>` : s.opts.public === false ? `<span class="pill mute">off</span>` : this.side(st.pub)}</td>
          <td>${s.internal ? this.side(st.int) : `<span class="pill mute">—</span>`}</td>
          <td>${Charts.spark(s.spark, { color })}</td>
          <td class="num">${fmt.pct(s.uptime24, 2)}</td><td class="num">${fmt.pct(s.uptime7, 2)}</td>
          <td class="small">${c.days != null ? `<span style="color:${c.days <= 3 ? "var(--crit)" : c.days <= 14 ? "var(--warn)" : "var(--muted)"}">${c.days} days</span>` : c.error ? `<span class="muted" title="${esc(c.error)}">no TLS</span>` : "<span class='muted'>–</span>"}</td>
          <td><button class="btn xs" data-act="site" data-host="${esc(s.host)}">Details</button></td></tr>`;
      }).join("")}</tbody></table>${excl ? `<div class="sub" style="padding:8px 14px">${excl} site${excl > 1 ? "s" : ""} not checked (Settings → Monitoring).</div>` : ""}`
      : `<div class="empty">No sites yet. Hostnames from your tunnels and HAProxy host rules show up here automatically${can("operator") ? ", or add one with “+ Add a check”" : ""}.</div>`;
  },

  bar(pct, warn, crit) {
    const cls = pct >= crit ? "crit" : pct >= warn ? "warn" : "";
    return `<span class="mbar ${cls}"><i style="width:${Math.min(100, pct || 0)}%"></i></span>`;
  },

  servers(d) {
    const cfg = d.settings;
    $("#monServers").innerHTML = d.servers.length ? `<table><thead><tr><th>Server</th><th>Type</th><th>CPU load</th><th>Memory</th><th>Disk (fullest)</th><th>Up</th><th>Watched services</th></tr></thead><tbody>
      ${d.servers.map((s) => {
        const type = { haproxy: "HAProxy", cloudflared: "cloudflared", server: "Server" }[s.kind];
        if (!s.at && !s.error) return `<tr><td><b>${esc(s.name)}</b><div class="sub mono">${esc(s.host)}</div></td><td><span class="tag">${type}</span></td><td colspan="5" class="muted">not read yet</td></tr>`;
        const stale = s.error ? `<td colspan="4">${pill("crit", "unreachable")} <span class="sub">${esc(s.error)}</span></td>` : "";
        const load = s.load ? s.load[0] : 0, lp = (load / (s.cores || 1)) * 100;
        const f = s.fullest || {};
        const svcs = s.watched.map((w) => {
          const ok = w.state === "active", unk = w.state === "unknown";
          return `<span class="svc ${ok ? "" : unk ? "unk" : "down"}"><span class="d"></span>${esc(w.unit.replace(/\.service$/, ""))}${ok || unk ? "" : ` · ${esc(w.state)}`}
            <button class="op" title="Stop watching" data-act="unwatch" data-node="${esc(s.name)}" data-unit="${esc(w.unit)}">✕</button></span>${!ok && !unk ? `<button class="btn xs pri op" data-act="restart" data-node="${esc(s.name)}" data-unit="${esc(w.unit)}">Restart</button> ` : ""}`;
        }).join("");
        return `<tr><td><b>${esc(s.name)}</b><div class="sub mono">${esc(s.host)}</div></td><td><span class="tag">${type}</span></td>
          ${stale || `<td>${this.bar(lp, cfg.load_factor * 50, cfg.load_factor * 100)}${load.toFixed(2)} <span class="sub">/ ${s.cores} cores</span></td>
          <td>${this.bar(s.mem_pct, cfg.mem_crit - 15, cfg.mem_crit)}${fmt.pct(s.mem_pct, 0)}${s.mem_total ? ` <span class="sub">of ${fmt.bytes(s.mem_total)}</span>` : ""}</td>
          <td>${f.pct != null ? `${this.bar(f.pct, cfg.disk_warn, cfg.disk_crit)}<span style="${f.pct >= cfg.disk_warn ? "color:var(--warn);font-weight:600" : ""}">${fmt.pct(f.pct, 0)}</span> <span class="sub">${esc(f.mount)}</span>` : "–"}</td>
          <td>${fmt.dur(s.uptime)}</td>`}
          <td>${svcs}<button class="btn xs ghost op" data-act="watch" data-node="${esc(s.name)}" title="Watch a service on ${esc(s.name)}">+ service</button></td></tr>`;
      }).join("")}</tbody></table>` : `<div class="empty">No nodes yet.</div>`;
  },

  async charts(d) {
    const r = this.range;
    const pubSites = d.sites.filter((s) => !s.excluded && s.state.pub).sort((a, b) => (b.state.pub.ms || 0) - (a.state.pub.ms || 0)).slice(0, 4);
    const mem = [...d.servers].filter((s) => s.mem_pct != null).sort((a, b) => b.mem_pct - a.mem_pct).slice(0, 4);
    const load = [...d.servers].filter((s) => s.load).sort((a, b) => b.load[0] / b.cores - a.load[0] / a.cores).slice(0, 4);
    const disk = [...d.servers].filter((s) => s.fullest).sort((a, b) => b.fullest.pct - a.fullest.pct).slice(0, 4);
    const be = d.top_backends || [];
    const defs = [
      { id: "c-rt", title: "Response time — public", meta: "per site", names: pubSites.map((s) => [`site.pub.ms:${s.host}`, s.host]), yFmt: fmt.ms },
      { id: "c-mem", title: "Memory used", meta: "% per server", names: mem.map((s) => [`srv.mem:${s.name}`, s.name]), yFmt: (v) => fmt.pct(v, 0), yMax: 100 },
      { id: "c-load", title: "CPU load", meta: "1-minute load average", names: load.map((s) => [`srv.load:${s.name}`, s.name]), yFmt: (v) => v.toFixed(2), minMax: 1 },
      { id: "c-disk", title: "Disk (fullest)", meta: "% used", names: disk.map((s) => [`srv.disk:${s.name}`, s.name]), yFmt: (v) => fmt.pct(v, 0), yMax: 100 },
      { id: "c-req", title: "Requests — HAProxy backends", meta: "per minute", names: be.map((n) => [`hp.req:${n}`, n.replace("/be:", " / ")]), yFmt: (v) => fmt.k(v), minMax: 4 },
      { id: "c-5xx", title: "5xx errors — HAProxy backends", meta: "per minute", names: be.map((n) => [`hp.5xx:${n}`, n.replace("/be:", " / ")]), yFmt: (v) => fmt.k(v), minMax: 4 },
      { id: "c-conn", title: "Connections", meta: "HAProxy, peak per minute", names: (d.hp_nodes || []).slice(0, 4).map((n) => [`hp.conn:${n}`, n]), yFmt: (v) => fmt.k(v), minMax: 4 },
    ].filter((c) => c.names.length);
    const box = $("#monCharts");
    if (!box) return;
    const keep = box.dataset.sig === JSON.stringify(defs.map((c) => [c.id, c.names]));
    if (!keep) {
      box.dataset.sig = JSON.stringify(defs.map((c) => [c.id, c.names]));
      box.innerHTML = defs.map((c) => `<div class="panel"><div class="hd"><h2>${esc(c.title)}</h2><span class="meta">${esc(c.meta)}</span></div><div class="chart" id="${c.id}"></div></div>`).join("");
    }
    const all = defs.flatMap((c) => c.names.map((n) => n[0]));
    if (!all.length) return;
    const s = await api(`/api/monitor/series?range=${r}&names=${encodeURIComponent(all.join(","))}`);
    if (S.page !== "monitoring") return;
    const span = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": SEVEN }[r];
    const xFmt = r === "7d" ? (t) => new Date(t * 1000).toLocaleDateString([], { weekday: "short" }) : undefined;
    for (const c of defs) {
      const el = $(`#${c.id}`);
      if (el) Charts.line(el, c.names.map(([k, label]) => ({ name: label, data: s.series[k] || [] })), { yFmt: c.yFmt, yMax: c.yMax, minMax: c.minMax, xFmt, legend: true, gap: span / 20, span });
    }
  },

  async onClick(e) {
    const rb = e.target.closest("#monRange button");
    if (rb) {
      this.range = rb.dataset.r;
      $$("#monRange button").forEach((b) => b.classList.toggle("on", b === rb));
      return this.charts(S.cache.mon);
    }
    const b = e.target.closest("[data-act]");
    const row = e.target.closest("tr[data-site]");
    if (!b && row) return this.details(row.dataset.site);
    if (!b) return;
    const ds = b.dataset;
    if (ds.act === "site") return this.details(ds.host);
    if (ds.act === "run") {
      busy(b, true);
      try { await api("/api/monitor/run", { body: {} }); toast("Checked everything", "ok"); refresh(); }
      catch (err) { toast(err.message, "bad"); } finally { busy(b, false); }
    }
    if (ds.act === "addsite") return this.addSite();
    if (ds.act === "watch") return this.watch(ds.node);
    if (ds.act === "unwatch") {
      if (!(await confirmBox(`Stop watching ${ds.unit}?`, `<p>${esc(ds.node)} keeps running it; the dashboard just stops alerting about it.</p>`, "Stop watching"))) return;
      try { await api(`/api/monitor/services/${encodeURIComponent(ds.node)}/${encodeURIComponent(ds.unit)}`, { method: "DELETE" }); refresh(); }
      catch (err) { toast(err.message, "bad"); }
    }
    if (ds.act === "restart") {
      if (!(await confirmBox(`Restart ${ds.unit}?`, `<p>Runs <code>systemctl restart ${esc(ds.unit)}</code> on <b>${esc(ds.node)}</b>.</p>`, "Restart"))) return;
      busy(b, true);
      try {
        const r = await api("/api/monitor/services/restart", { body: { node: ds.node, unit: ds.unit } });
        r.ok ? toast(`${ds.unit} is running again`, "ok") : showOutput(`${ds.unit} did not start`, r);
      } catch (err) { toast(err.message, "bad"); } finally { busy(b, false); refresh(); }
    }
  },

  async addSite() {
    const changed = await taskModal({
      title: "Add a check", submit: "Add & check", size: "",
      html: `<div class="two"><label>Hostname<input name="host" type="text" placeholder="status.example.com" required autocomplete="off"></label>
        <label>Kind<select name="kind"><option value="http">Website (HTTP)</option><option value="tcp">TCP port</option></select></label></div>
        <label>Internal address <span class="muted">(optional for websites)</span><input name="internal" type="text" placeholder="http://10.0.10.21:8080 or tcp://10.0.10.21:25565" autocomplete="off">
          <div class="hint">Checked straight from this dashboard, with the hostname as the Host header.</div></label>
        <label class="check"><input type="checkbox" name="public" checked> Also check it publicly (https://hostname/)</label>`,
      run: (fd) => api("/api/monitor/sites", { body: fd }),
    });
    if (changed) refresh();
  },

  async watch(node) {
    const f = document.createElement("div");
    f.innerHTML = `<p class="muted small" style="margin:0 0 8px">A stopped watched service raises an alert, and operators get a Restart button.</p>
      <div class="row"><input type="text" class="grow" placeholder="nginx, redis-server, php8.3-fpm…" data-unit><button class="btn pri" data-go>Watch</button></div>
      <div class="sub" style="margin:10px 0 4px">Running on ${esc(node)}:</div><div data-sug class="small muted">loading…</div><div class="ferr" data-err></div>`;
    const go = async (unit) => {
      try { await api("/api/monitor/services", { body: { node, unit } }); toast(`Watching ${unit} on ${node}`, "ok"); bg._close(true); refresh(); }
      catch (err) { $("[data-err]", f).textContent = err.message; }
    };
    let bg;
    f.addEventListener("click", (e) => {
      const s = e.target.closest("[data-u]");
      if (s) go(s.dataset.u);
      if (e.target.closest("[data-go]")) go($("[data-unit]", f).value.trim());
    });
    f.addEventListener("keydown", (e) => e.key === "Enter" && go($("[data-unit]", f).value.trim()));
    modal({ title: `Watch a service · ${node}`, body: f, onOpen: (b) => { bg = b; setTimeout(() => $("[data-unit]", f).focus(), 30); } });
    try {
      const r = await api(`/api/monitor/services/suggest/${encodeURIComponent(node)}`);
      $("[data-sug]", f).innerHTML = r.units.map((u) => `<button class="chip" style="cursor:pointer" data-u="${esc(u)}">${esc(u.replace(/\.service$/, ""))}</button>`).join("") || "nothing else running";
    } catch (err) { $("[data-sug]", f).textContent = err.message; }
  },

  async details(host) {
    const s = (S.cache.mon?.sites || []).find((x) => x.host === host);
    if (!s) return;
    const st = s.state, o = s.opts, r = s.route || {};
    const f = document.createElement("div");
    const route = r.frontend ? `${r.tunnel ? `tunnel <b>${esc(r.tunnel.name)}</b><span class="arr">→</span>` : ""}${esc(s.internal)}<span class="arr">→</span>HAProxy <b>${esc(r.frontend)}</b><span class="arr">→</span><b>${esc(r.backend || "?")}</b>`
      : r.tunnel ? `tunnel <b>${esc(r.tunnel.name)}</b><span class="arr">→</span>${esc(s.internal)} (not through HAProxy)` : esc(s.internal || "public only");
    f.innerHTML = `<div class="mini" style="margin-bottom:12px">
        <div><div class="l">Public</div><div class="v">${s.kind === "tcp" || o.public === false ? "—" : this.side(st.pub)}</div></div>
        <div><div class="l">Internal</div><div class="v">${s.internal ? this.side(st.int) : "—"}</div></div>
        <div><div class="l">Uptime 24 h · 7 days</div><div class="v">${fmt.pct(s.uptime24, 2)} · ${fmt.pct(s.uptime7, 2)}</div></div></div>
      <div class="route" style="margin-bottom:12px">${route}</div>
      ${st.cert?.days != null ? `<div class="small muted" style="margin-bottom:10px">Certificate ${st.cert.issuer ? `from ${esc(st.cert.issuer)} ` : ""}expires in <b>${st.cert.days} days</b>.</div>` : ""}
      <div class="row" style="justify-content:space-between"><b class="small">Response time</b><span class="segs" data-rg>${["1h", "24h", "7d"].map((x) => `<button data-r="${x}" class="${x === "24h" ? "on" : ""}">${x}</button>`).join("")}</span></div>
      <div class="chart" style="padding:8px 0" data-ch></div>
      <form class="form op" data-opts style="margin-top:6px"><div class="sep">Check options</div>
        <div class="two"><label>Path<input name="path" type="text" value="${esc(o.path || "")}" placeholder="/"></label>
          <label>Expected status<input name="expect" type="text" value="${esc(o.expect ?? "")}" placeholder="any below 500"></label></div>
        <div class="two"><label>Page must contain<input name="keyword" type="text" value="${esc(o.keyword || "")}" placeholder="optional"></label>
          <label>Slow above (ms)<input name="slow_ms" type="text" value="${esc(o.slow_ms ?? "")}" placeholder="${s.slow_ms}"></label></div>
        ${s.kind === "http" ? `<label class="check"><input type="checkbox" name="public" ${o.public !== false ? "checked" : ""}> Check it publicly through Cloudflare</label>` : ""}
        <div class="row"><button class="btn pri" type="submit">Save</button><span class="grow"></span>
          ${s.source === "manual" ? `<button class="btn danger" type="button" data-del>Delete check</button>` : `<button class="btn" type="button" data-excl>Don't check this site</button>`}</div>
        <div class="ferr" data-err></div></form>`;
    let bg;
    const draw = async (rg) => {
      const side = st.pub ? "pub" : "int";
      const names = [`site.pub.ms:${host}`, `site.int.ms:${host}`];
      const d = await api(`/api/monitor/series?range=${rg}&names=${encodeURIComponent(names.join(","))}`);
      Charts.line($("[data-ch]", f), [{ name: "public", data: d.series[names[0]] }, { name: "internal", data: d.series[names[1]] }].filter((x) => x.data.length),
        { yFmt: fmt.ms, h: 180, legend: true, span: { "1h": 3600, "24h": 86400, "7d": SEVEN }[rg], gap: { "1h": 300, "24h": 3600, "7d": 21600 }[rg], xFmt: rg === "7d" ? (t) => new Date(t * 1000).toLocaleDateString([], { weekday: "short" }) : undefined });
      return side;
    };
    f.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-rg] button");
      if (b) { $$("[data-rg] button", f).forEach((x) => x.classList.toggle("on", x === b)); draw(b.dataset.r); }
      if (e.target.closest("[data-excl]")) {
        try { await api(`/api/monitor/sites/${encodeURIComponent(host)}`, { method: "PUT", body: { excluded: true } }); toast(`${host} is no longer checked`, "ok"); bg._close(true); refresh(); }
        catch (err) { $("[data-err]", f).textContent = err.message; }
      }
      if (e.target.closest("[data-del]")) {
        try { await api(`/api/monitor/sites/${encodeURIComponent(host)}`, { method: "DELETE" }); bg._close(true); refresh(); }
        catch (err) { $("[data-err]", f).textContent = err.message; }
      }
    });
    $("[data-opts]", f).addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      const pub = $("[name=public]", e.target);
      if (pub) fd.public = pub.checked;
      try { await api(`/api/monitor/sites/${encodeURIComponent(host)}`, { method: "PUT", body: fd }); toast("Saved — checked again", "ok"); bg._close(true); refresh(); }
      catch (err) { $("[data-err]", f).textContent = err.message; }
    });
    modal({ title: host, body: f, size: "lg", onOpen: (b) => { bg = b; draw("24h"); } });
  },
};
