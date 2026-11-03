/* Gateway Console web UI — HAProxy page: live runtime stats per node, server ready/drain/maint,
 * reload/restart, logs, and "Edit config" which opens the side-panel editor. */
"use strict";

// shared with Settings → Nodes: add / fix the admin stats socket (safe apply on the node)
async function fixStatsSocket(node) {
  const ok = await confirmBox(`Set up the admin stats socket on ${node}?`,
    `<p>Adds <code>stats socket … mode 660 level admin</code> to the <code>global</code> section of haproxy.cfg
      (or raises an existing socket to <code>level admin</code>) and installs <code>socat</code> if it's missing.</p>
     <p>Same safe path as the editor: <code>haproxy -c</code> first, a backup, a graceful reload, automatic rollback on failure.</p>`, "Fix it");
  if (!ok) return null;
  const r = await api(`/api/haproxy/${encodeURIComponent(node)}/fix-socket`, { body: {} });
  showOutput(r.ok ? "Stats socket ready" : "Stats socket not fixed", r);
  return r;
}

PAGES.haproxy = {
  every: 5,
  mount(v, params) {
    const nodes = S.inv.haproxy;
    const cur = params[0] || nodes[0]?.name;
    S.cache.hpNode = cur;
    setHeader("HAProxy", "Live runtime stats · server state · service control");
    if (!nodes.length) { v.innerHTML = `<div class="panel"><div class="empty">No HAProxy nodes yet.${S.role === "superadmin" ? ` <a href="#/settings/nodes">Add one in Settings → Nodes</a>.` : ""}</div></div>`; return; }
    v.innerHTML = `<div class="row">${nodes.length > 1 ? `<div class="seg">${nodes.map((n) => `<button class="${n.name === cur ? "on" : ""}" data-node="${esc(n.name)}">${esc(n.name)}${n.site ? ` · ${esc(n.site)}` : ""}</button>`).join("")}</div>` : ""}
        <div class="grow"></div><input type="search" id="hpFilter" placeholder="Filter backends / servers…" value="${esc(S.cache.hpFilter || "")}"></div>
      <div class="panel" id="hpHead"><div class="empty">Loading…</div></div>
      <div class="panel"><div class="hd"><h2>Frontends</h2></div><div class="bd flush tbl-wrap" id="hpFe"></div></div>
      <div class="panel"><div class="hd"><h2>Backends & servers</h2><span class="meta">State changes are runtime-only (lost on restart). Use Edit config to make them permanent.</span></div><div class="bd flush tbl-wrap" id="hpBe"></div></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
    $("#hpFilter").addEventListener("input", (e) => { S.cache.hpFilter = e.target.value; if (S.cache.hp) this.renderBe(S.cache.hp); });
  },
  async load() {
    const node = S.cache.hpNode;
    if (!node) return;
    const d = await api(`/api/haproxy/${encodeURIComponent(node)}`);
    if (S.page !== "haproxy" || S.cache.hpNode !== node) return;
    S.cache.hp = d;
    const i = d.info;
    $("#hpHead").innerHTML = `<div class="hd"><h2>${esc(d.node)}</h2><span class="meta mono">${esc(d.host)}</span>${pill(svcClass(d.service.active), d.service.active)}
        <div class="acts"><button class="btn sm" data-act="logs">Logs</button><button class="btn sm pri" data-act="edit">Edit config</button>
        <button class="btn sm op" data-act="svc" data-a="reload">Reload</button><button class="btn sm danger op" data-act="svc" data-a="restart">Restart</button></div></div>
      <div class="bd"><dl class="kv" style="grid-template-columns:repeat(auto-fit,minmax(110px,auto) minmax(120px,1fr))">
        <dt>Version</dt><dd>${esc(i.Version || "–")}</dd><dt>Uptime</dt><dd>${fmt.dur(i.Uptime_sec)}</dd>
        <dt>Connections</dt><dd>${fmt.n(i.CurrConns)} / ${fmt.n(i.Maxconn)}</dd><dt>Conn rate</dt><dd>${fmt.n(i.ConnRate)}/s</dd>
        <dt>Sess rate</dt><dd>${fmt.n(i.SessRate)}/s</dd><dt>Total req</dt><dd>${fmt.n(i.CumReq)}</dd>
        <dt>Threads</dt><dd>${esc(i.Nbthread || "–")}</dd><dt>Idle</dt><dd>${i.Idle_pct != null ? esc(i.Idle_pct) + "%" : "–"}</dd>
        <dt>Service since</dt><dd>${esc(d.service.since || "–")}</dd></dl>
        ${d.stats_error ? `<div class="out bad" style="margin-top:12px">${esc(d.stats_error)}</div>
          <div class="row op" style="margin-top:8px"><button class="btn sm pri" data-act="fixsock">Set up the stats socket for me</button>
          <span class="muted small">validated, backed up, rolled back on error</span></div>` : ""}</div>`;
    $("#hpFe").innerHTML = d.frontends.length ? `<table><thead><tr><th>Frontend</th><th>Status</th><th>Mode</th><th class="num">Sessions</th><th class="num">Rate/s</th><th class="num">Req/s</th>
      <th class="num">In</th><th class="num">Out</th><th class="num">2xx</th><th class="num">4xx</th><th class="num">5xx</th><th class="num">Req err</th></tr></thead><tbody>
      ${d.frontends.map((f) => `<tr><td><b>${esc(f.name)}</b></td><td>${pill(srvClass(f.status), f.status)}</td><td>${esc(f.mode)}</td>
        <td class="num">${fmt.n(f.scur)} <span class="sub">/ ${fmt.n(f.slim)}</span></td><td class="num">${fmt.n(f.rate)}</td><td class="num">${f.mode === "http" ? fmt.n(f.req_rate) : "–"}</td>
        <td class="num">${fmt.bytes(f.bin)}</td><td class="num">${fmt.bytes(f.bout)}</td>
        <td class="num">${fmt.n(f.hrsp_2xx)}</td><td class="num">${fmt.n(f.hrsp_4xx)}</td><td class="num">${fmt.n(f.hrsp_5xx)}</td><td class="num">${fmt.n(f.ereq)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">No frontends.</div>`;
    this.renderBe(d);
  },
  renderBe(d) {
    const q = (S.cache.hpFilter || "").toLowerCase();
    const rows = d.backends.map((b) => {
      const servers = b.servers.filter((s) => !q || b.name.toLowerCase().includes(q) || s.name.toLowerCase().includes(q) || (s.addr || "").includes(q));
      if (q && !servers.length) return "";
      const up = b.servers.filter((s) => srvClass(s.status) === "ok").length;
      return `<tr class="be-row"><td>${esc(b.name)}</td><td>${pill(srvClass(b.status), b.status)}</td><td colspan="2" class="sub">${up}/${b.servers.length} servers up · ${esc(b.mode)}</td>
          <td class="num">${fmt.n(b.scur)}</td><td class="num">${fmt.n(b.rate)}</td><td class="num">${fmt.bytes(b.bin)} / ${fmt.bytes(b.bout)}</td><td class="num">${fmt.n(b.hrsp_5xx)}</td><td></td></tr>` +
        servers.map((s) => {
          const st = s.status.includes("MAINT") ? "maint" : s.status === "DRAIN" || s.status.includes("DRAIN") ? "drain" : "ready";
          return `<tr><td style="padding-left:28px">${esc(s.name)}${s.backup ? ` <span class="tag">backup</span>` : ""}<div class="sub mono">${esc(s.addr)}</div></td>
            <td>${pill(srvClass(s.status), s.status)}</td>
            <td><span class="mono small">${esc(s.check_status || "–")}</span>${s.check_duration != null ? ` <span class="sub">${s.check_duration}ms</span>` : ""}<div class="sub">${esc(s.check_desc || "")}</div></td>
            <td class="sub">changed ${fmt.dur(s.lastchg)} ago${s.chkfail ? ` · ${s.chkfail} fails` : ""}</td>
            <td class="num">${fmt.n(s.scur)}</td><td class="num">${fmt.n(s.rate)}</td><td class="num">${fmt.bytes(s.bin)} / ${fmt.bytes(s.bout)}</td><td class="num">${fmt.n(s.hrsp_5xx)}</td>
            <td><div class="seg op">${["ready", "drain", "maint"].map((x) => `<button class="${x} ${st === x ? "on" : ""}" data-act="srv" data-be="${esc(b.name)}" data-srv="${esc(s.name)}" data-st="${x}">${x}</button>`).join("")}</div></td></tr>`;
        }).join("");
    }).join("");
    $("#hpBe").innerHTML = rows ? `<table><thead><tr><th>Backend / server</th><th>Status</th><th>Check</th><th>Last change</th><th class="num">Sess</th><th class="num">Rate/s</th><th class="num">In / out</th><th class="num">5xx</th><th>State</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="empty">${q ? "No match." : "No backends."}</div>`;
  },
  async onClick(e) {
    const nb = e.target.closest("[data-node]");
    if (nb) { location.hash = `#/haproxy/${encodeURIComponent(nb.dataset.node)}`; return; }
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const node = S.cache.hpNode;
    if (b.dataset.act === "edit") return Editor.open("haproxy", node);
    if (b.dataset.act === "fixsock") {
      busy(b, true);
      try { await fixStatsSocket(node); } catch (err) { toast(err.message, "bad"); } finally { busy(b, false); refresh(); }
      return;
    }
    if (b.dataset.act === "logs") {
      return showLogs(`HAProxy logs · ${node}`, (src, n) => api(`/api/haproxy/${encodeURIComponent(node)}/logs?source=${src}&lines=${n}`), [["service", "service"], ["access", "access log"]]);
    }
    if (b.dataset.act === "svc") {
      const a = b.dataset.a;
      const ok = await confirmBox(`${a === "reload" ? "Reload" : "Restart"} HAProxy on ${node}?`,
        a === "reload" ? "<p>Runs <code>haproxy -c</code> first, then a graceful <code>systemctl reload</code>. Existing connections are kept.</p>"
          : "<p><b>Restart drops all active connections</b> (including tunnel → HAProxy traffic). The config is checked first.</p>",
        a === "reload" ? "Reload" : "Restart", a === "reload" ? "pri" : "danger");
      if (!ok) return;
      busy(b, true);
      try { const r = await api(`/api/haproxy/${encodeURIComponent(node)}/service`, { body: { action: a } }); r.ok ? toast(`HAProxy ${a}ed on ${node}`, "ok") : showOutput(`${a} failed`, r); }
      catch (err) { toast(err.message, "bad"); } finally { busy(b, false); refresh(); }
    }
    if (b.dataset.act === "srv") {
      if (b.classList.contains("on")) return;
      const { be, srv, st } = b.dataset;
      if (st !== "ready") {
        const ok = await confirmBox(`Set ${be}/${srv} to ${st.toUpperCase()}?`,
          st === "drain" ? "<p>Stops new connections to this server; existing sessions finish normally.</p>" : "<p>Takes the server out of rotation immediately (maintenance). Health checks stop.</p>",
          `Set ${st}`, st === "maint" ? "danger" : "pri");
        if (!ok) return;
      }
      try { await api(`/api/haproxy/${encodeURIComponent(node)}/server`, { body: { backend: be, server: srv, state: st } }); toast(`${be}/${srv} → ${st}`, "ok"); }
      catch (err) { toast(err.message, "bad"); } finally { refresh(); }
    }
  },
};

