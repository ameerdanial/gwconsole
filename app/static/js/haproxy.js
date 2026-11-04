/* Gateway Console web UI — HAProxy page: six status tiles, live frontends and backends with
 * server ready/drain/maint, "+ Add" and Edit/Delete for frontends and backends (hpform.js),
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
      <div class="panel"><div class="hd"><h2>Backends & servers</h2><span class="meta">Drain and maintenance are kept after a restart (saved in haproxy.cfg, no reload) unless you untick it · 📌 = kept</span></div><div class="bd flush tbl-wrap" id="hpBe"></div></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
    $("#hpFilter").addEventListener("input", (e) => { S.cache.hpFilter = e.target.value; if (S.cache.hp) this.renderBe(S.cache.hp); });
  },
  async load() {
    const node = S.cache.hpNode;
    if (!node) return;
    const d = await api(`/api/haproxy/${encodeURIComponent(node)}`);
    if (S.page !== "haproxy" || S.cache.hpNode !== node) return;
    S.cache.hp = d;
    $("#hpHead").innerHTML = this.head(d);
    $("#hpFe").innerHTML = d.frontends.length ? `<table><thead><tr><th>Frontend</th><th>Status</th><th>Mode</th><th class="num">Sessions</th><th class="num">Rate/s</th><th class="num">Req/s</th>
      <th class="num">In</th><th class="num">Out</th><th class="num">2xx</th><th class="num">4xx</th><th class="num">5xx</th><th class="num">Req err</th><th></th></tr></thead><tbody>
      ${d.frontends.map((f) => `<tr><td><b>${esc(f.name)}</b></td><td>${pill(srvClass(f.status), f.status)}</td><td>${esc(f.mode)}</td>
        <td class="num">${fmt.n(f.scur)} <span class="sub">/ ${fmt.n(f.slim)}</span></td><td class="num">${fmt.n(f.rate)}</td><td class="num">${f.mode === "http" ? fmt.n(f.req_rate) : "–"}</td>
        <td class="num">${fmt.bytes(f.bin)}</td><td class="num">${fmt.bytes(f.bout)}</td>
        <td class="num">${fmt.n(f.hrsp_2xx)}</td><td class="num">${fmt.n(f.hrsp_4xx)}</td><td class="num">${fmt.n(f.hrsp_5xx)}</td><td class="num">${fmt.n(f.ereq)}</td>
        <td class="op"><button class="btn xs" data-act="edit-fe" data-name="${esc(f.name)}">${d.scoped ? "Edit my rules" : "Edit"}</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">No frontends.</div>`;
    this.renderBe(d);
  },
  head(d) {
    const i = d.info, sv = d.service;
    const be = d.backends, beUp = be.filter((b) => srvClass(b.status) === "ok").length;
    const servers = be.flatMap((b) => b.servers);
    const sUp = servers.filter((x) => srvClass(x.status) === "ok").length;
    const sMaint = servers.filter((x) => /MAINT|DRAIN/.test(x.status)).length;
    const sDown = servers.length - sUp - sMaint;
    const sum = (k) => d.frontends.reduce((a, f) => a + (f[k] || 0), 0);
    const req = +(i.CumReq || 0), e5 = sum("hrsp_5xx"), tot = sum("hrsp_2xx") + sum("hrsp_3xx") + sum("hrsp_4xx") + e5;
    const conn = +(i.CurrConns || 0), max = +(i.Maxconn || 0), pct = max ? (conn / max) * 100 : 0;
    const ver = String(i.Version || "–"), vMain = ver.split("-")[0], vPkg = ver.includes("-") ? ver.slice(ver.indexOf("-") + 1) : "";
    const since = sv.since_epoch ? `${fmt.wd(sv.since_epoch)} ${fmt.short(sv.since_epoch)}` : (sv.since || "–");
    const up = sv.since_epoch ? Math.max(0, Math.round(Date.now() / 1000 - sv.since_epoch)) : +i.Uptime_sec;
    return `<div class="hd"><h2>${esc(d.node)}</h2><span class="meta mono">${esc(d.host)}</span>${d.site ? `<span class="tag">${esc(d.site)}</span>` : ""}${pill(svcClass(sv.active), sv.active)}
        ${d.scoped ? "" : `<div class="acts"><button class="btn sm" data-act="logs">Logs</button><button class="btn sm" data-act="edit">Edit config</button>
        <button class="btn sm pri op" data-act="add">+ Add</button>
        <button class="btn sm op" data-act="svc" data-a="reload">Reload</button><button class="btn sm danger op" data-act="svc" data-a="restart">Restart</button></div>`}</div>
      <div class="tiles">
        <div class="tile"><div class="l">Service</div><div class="v">${sv.active === "active" ? fmt.dur(up) : esc(sv.active)}${sv.active === "active" ? " <small>up</small>" : ""}</div>
          <div class="s">since ${esc(since)}</div><div class="s">${sv.restarts != null ? `${sv.restarts} automatic restart${sv.restarts === 1 ? "" : "s"}` : ""}</div></div>
        <div class="tile"><div class="l">Backends</div><div class="v ${beUp === be.length ? "okc" : "critc"}">${beUp}<small> / ${be.length} up</small></div>
          <div class="chips">${pill("ok", `${sUp} server${sUp === 1 ? "" : "s"} up`)}${sMaint ? pill("warn", `${sMaint} drain/maint`) : ""}${sDown ? pill("crit", `${sDown} down`) : ""}</div></div>
        ${d.scoped ? "" : `<div class="tile"><div class="l">Connections</div><div class="v">${fmt.n(conn)} <small>/ ${fmt.n(max)}</small></div>
          <div class="meter ${pct > 80 ? "crit" : pct > 60 ? "warn" : ""}"><i style="width:${Math.min(100, Math.max(pct, conn ? 1 : 0)).toFixed(1)}%"></i></div><div class="s">${pct.toFixed(pct < 1 ? 2 : 0)}% of maxconn</div></div>
        <div class="tile"><div class="l">Rates now</div><div class="mini3"><b>${fmt.n(i.ConnRate)}</b><b>${fmt.n(i.SessRate)}</b><b>${fmt.n(sum("req_rate"))}</b><span>conn/s</span><span>sess/s</span><span>req/s</span></div></div>
        <div class="tile"><div class="l">Traffic</div><div class="v">${fmt.n(req)} <small>requests</small></div>
          <div class="s">↓ ${fmt.bytes(sum("bin"))} in · ↑ ${fmt.bytes(sum("bout"))} out</div><div class="s">5xx: ${fmt.n(e5)}${tot ? ` (${((e5 / tot) * 100).toFixed(e5 && e5 / tot < 0.01 ? 2 : 1)}%)` : ""}</div></div>
        <div class="tile"><div class="l">HAProxy</div><div class="v">${esc(vMain)}</div><div class="s">${vPkg ? `package ${esc(vPkg)}` : esc(i.Release_date || "")}</div>
          <div class="s">${esc(i.Nbthread || "–")} thread${i.Nbthread === "1" ? "" : "s"} · CPU idle ${i.Idle_pct != null ? esc(i.Idle_pct) + "%" : "–"}</div></div>`}
      </div>
      ${d.stats_error && !d.scoped ? `<div class="bd"><div class="out bad">${esc(d.stats_error)}</div>
        <div class="row op" style="margin-top:8px"><button class="btn sm pri" data-act="fixsock">Set up the stats socket for me</button>
        <span class="muted small">validated, backed up, rolled back on error</span></div></div>` : ""}`;
  },
  renderBe(d) {
    const q = (S.cache.hpFilter || "").toLowerCase();
    const rows = d.backends.map((b) => {
      const servers = b.servers.filter((s) => !q || b.name.toLowerCase().includes(q) || s.name.toLowerCase().includes(q) || (s.addr || "").includes(q));
      if (q && !servers.length) return "";
      const up = b.servers.filter((s) => srvClass(s.status) === "ok").length;
      return `<tr class="be-row"><td>${esc(b.name)}</td><td>${pill(srvClass(b.status), b.status)}</td><td colspan="2" class="sub">${up}/${b.servers.length} servers up · ${esc(b.mode)}</td>
          <td class="num">${fmt.n(b.scur)}</td><td class="num">${fmt.n(b.rate)}</td><td class="num">${fmt.bytes(b.bin)} / ${fmt.bytes(b.bout)}</td><td class="num">${fmt.n(b.hrsp_5xx)}</td>
          <td>${b.locked ? `<span class="lockt" title="Other sites also use this backend, so it's read-only for you">🔒 shared · read only</span>` : `<div class="row op" style="flex-wrap:nowrap;gap:4px;justify-content:flex-end"><button class="btn xs" data-act="add-srv" data-name="${esc(b.name)}">+ server</button>
            <button class="btn xs" data-act="edit-be" data-name="${esc(b.name)}">Edit</button><button class="btn xs danger" data-act="del-be" data-name="${esc(b.name)}">Delete</button></div>`}</td></tr>` +
        servers.map((s) => {
          const st = s.status.includes("MAINT") ? "maint" : s.status === "DRAIN" || s.status.includes("DRAIN") ? "drain" : "ready";
          return `<tr><td style="padding-left:28px">${esc(s.name)}${s.backup ? ` <span class="tag">backup</span>` : ""}<div class="sub mono">${esc(s.addr)}</div></td>
            <td>${pill(srvClass(s.status), s.status)}${s.kept ? `<span class="kept" title="Kept after restart: haproxy.cfg has ${s.kept === "maint" ? "'disabled'" : "'weight 0'"} on this server">📌</span>` : ""}
              ${s.kept && s.kept !== st ? `<div><span class="pill mis" title="Running state and haproxy.cfg disagree — after a reload it goes back to ${s.kept}">file says ${esc(s.kept)}</span></div>` : ""}
              ${!s.kept && st !== "ready" && s.kept !== undefined ? `<div class="sub">until restart</div>` : ""}</td>
            <td><span class="mono small">${esc(s.check_status || "–")}</span>${s.check_duration != null ? ` <span class="sub">${s.check_duration}ms</span>` : ""}<div class="sub">${esc(s.check_desc || "")}</div></td>
            <td class="sub">changed ${fmt.dur(s.lastchg)} ago${s.chkfail ? ` · ${s.chkfail} fails` : ""}</td>
            <td class="num">${fmt.n(s.scur)}</td><td class="num">${fmt.n(s.rate)}</td><td class="num">${fmt.bytes(s.bin)} / ${fmt.bytes(s.bout)}</td><td class="num">${fmt.n(s.hrsp_5xx)}</td>
            <td>${b.locked ? "" : `<div class="row" style="flex-wrap:nowrap;gap:6px;justify-content:flex-end"><div class="seg op">${["ready", "drain", "maint"].map((x) => `<button class="${x} ${st === x ? "on" : ""}" data-act="srv" data-be="${esc(b.name)}" data-srv="${esc(s.name)}" data-st="${x}" data-kept="${esc(s.kept || "")}">${x}</button>`).join("")}</div>
              <button class="ib rm op" title="Remove ${esc(s.name)} from haproxy.cfg" data-act="rm-srv" data-be="${esc(b.name)}" data-srv="${esc(s.name)}">✕</button></div>`}</td></tr>`;
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
    const run = async (fn) => { busy(b, true); try { await fn(); } catch (err) { toast(err.message, "bad"); } finally { busy(b, false); } };
    if (b.dataset.act === "add") return run(() => HPF.open(node));
    if (b.dataset.act === "edit-fe") return run(() => HPF.open(node, { mode: "edit", kind: "frontend", name: b.dataset.name }));
    if (b.dataset.act === "edit-be") return run(() => HPF.open(node, { mode: "edit", kind: "backend", name: b.dataset.name }));
    if (b.dataset.act === "add-srv") return run(() => HPF.open(node, { mode: "edit", kind: "backend", name: b.dataset.name, addServer: true }));
    if (b.dataset.act === "del-be") return run(async () => { await HPF.open(node, { mode: "edit", kind: "backend", name: b.dataset.name }); await HPF.remove(); });
    if (b.dataset.act === "rm-srv") {
      const { be, srv } = b.dataset;
      return run(() => HPF.quick(node, "backend", be, (m) => { m.servers = m.servers.filter((x) => x.name !== srv); }, `Remove ${srv} from ${be}`));
    }
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
      const { be, srv, st, kept } = b.dataset;
      if (b.classList.contains("on") && (kept || "ready") === st) return;
      let keep = true;
      const what = st === "drain" ? "<p>Stops new connections to this server; existing sessions finish normally.</p>"
        : st === "maint" ? "<p>Takes the server out of rotation immediately (maintenance). Health checks stop.</p>"
        : "<p>Puts the server back into rotation.</p>";
      const tick = st === "ready" ? (kept ? `<label class="check"><input type="checkbox" data-keep checked> Also remove the kept ${esc(kept)} from haproxy.cfg (no reload)</label>` : "")
        : `<label class="check"><input type="checkbox" data-keep checked> Keep after restart — save it in haproxy.cfg as <code>${st === "maint" ? "disabled" : "weight 0"}</code> (no reload)</label>`;
      if (st !== "ready" || kept) {
        const ok = await modal({ title: st === "ready" ? `Set ${be}/${srv} to READY?` : `Set ${be}/${srv} to ${st.toUpperCase()}?`, size: "sm",
          body: `${what}<div class="form" style="margin-top:8px">${tick}</div>`,
          actions: [{ label: "Cancel", value: false }, { label: `Set ${st}`, cls: st === "maint" ? "danger" : "pri", value: true }],
          onOpen: (bg) => bg.addEventListener("change", (ev) => { if (ev.target.matches("[data-keep]")) keep = ev.target.checked; }) });
        if (!ok) return;
      } else keep = false;
      try {
        const r = await api(`/api/haproxy/${encodeURIComponent(node)}/server`, { body: { backend: be, server: srv, state: st, keep } });
        toast(`${be}/${srv} → ${st}${keep && st !== "ready" ? " · kept after restart" : ""}`, "ok");
        if (/already/.test(r.output || "")) toast(r.output, "");
      }
      catch (err) { toast(err.message, "bad"); } finally { refresh(); }
    }
  },
};

