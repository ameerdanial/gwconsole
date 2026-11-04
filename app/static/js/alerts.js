/* Gateway Console web UI — Alerts page: active and historical alerts from the background
 * checker, with acknowledge, mute (per alert or a whole node for maintenance) and CSV export. */
"use strict";

PAGES.alerts = {
  every: 15,
  mount(v, params) {
    setHeader("Alerts", "Everything that went wrong, when it started and how long it lasted");
    const f = S.cache.alertFilter || (S.cache.alertFilter = { tab: "active", sev: "", q: "", days: 7 });
    if (params[0] === "history") f.tab = "history";
    v.innerHTML = `
      <div class="panel"><div class="bd row">
        <div class="seg" id="alTabs"><button data-tab="active">Active</button><button data-tab="history">History</button></div>
        <select id="alSev"><option value="">All severities</option><option value="crit">Critical</option><option value="warn">Warning</option></select>
        <select id="alDays" class="hist-only"><option value="1">Last 24 h</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></select>
        <input type="search" id="alQ" placeholder="Search target or message…" class="grow" style="min-width:160px">
        <a class="btn sm" id="alCsv">Export CSV</a>
        <button class="btn sm op" id="alCheck" title="Run all checks now">Check now</button>
      </div><div class="bd muted small" id="alStatus" style="padding-top:0"></div></div>
      <div class="panel"><div class="bd flush tbl-wrap" id="alTable"><div class="empty">Loading…</div></div></div>
      <div class="panel"><div class="hd"><h2>Mutes</h2><span class="meta">Muted alerts are still recorded but don't notify. Use a node mute for maintenance.</span>
        <div class="acts"><button class="btn sm op" id="alMuteNode">Mute a node…</button></div></div>
        <div class="bd flush tbl-wrap" id="alMutes"></div></div>`;
    $("#alSev").value = f.sev; $("#alDays").value = String(f.days); $("#alQ").value = f.q;
    const sync = () => {
      $$("#alTabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === f.tab));
      $$(".hist-only").forEach((x) => x.classList.toggle("hidden", f.tab !== "history"));
      const qs = new URLSearchParams({ state: f.tab, sev: f.sev, q: f.q, days: f.days });
      $("#alCsv").href = `/api/alerts/export.csv?${qs}`;
    };
    sync();
    let t;
    $("#alTabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) { f.tab = b.dataset.tab; sync(); refresh(true); } });
    $("#alSev").addEventListener("change", (e) => { f.sev = e.target.value; sync(); refresh(true); });
    $("#alDays").addEventListener("change", (e) => { f.days = +e.target.value; sync(); refresh(true); });
    $("#alQ").addEventListener("input", (e) => { f.q = e.target.value; sync(); clearTimeout(t); t = setTimeout(() => refresh(true), 300); });
    $("#alCheck").addEventListener("click", async (e) => {
      busy(e.target, true);
      try { const r = await api("/api/alerts/check", { body: {} }); toast(`Checked: ${r.active} active, ${fmt.plural(r.changes, "change")}`, "ok"); }
      catch (err) { toast(err.message, "bad"); } finally { busy(e.target, false); refresh(true); updateBadge(); }
    });
    $("#alMuteNode").addEventListener("click", () => this.muteNode());
    v.addEventListener("click", (e) => this.onClick(e));
    v.addEventListener("change", (e) => this.onChange(e));
  },

  async load() {
    const f = S.cache.alertFilter;
    const qs = new URLSearchParams({ state: f.tab, sev: f.sev, q: f.q, days: f.days });
    const [d, m, s] = await Promise.all([api(`/api/alerts?${qs}`), api("/api/mutes"), api("/api/alerts/summary")]);
    if (S.page !== "alerts") return;
    S.cache.alerts = d.items; S.cache.mutes = m.items;
    $$("#alTabs button")[0].textContent = `Active (${s.active})`;
    $("#alStatus").innerHTML = s.last_run
      ? `Checked every ${s.interval} s · last check ${fmt.ago(s.last_run)}${s.last_error ? ` · <span style="color:var(--crit)">${esc(s.last_error)}</span>` : ""}`
      : "Waiting for the first check…";
    const rows = d.items;
    $("#alTable").innerHTML = rows.length ? `<table><thead><tr><th>Sev</th><th>Target</th><th>Message</th><th>Started</th><th>Duration</th><th>Status</th><th></th></tr></thead><tbody>
      ${rows.map((a) => `<tr class="${a.status === "resolved" || a.muted ? "dim" : ""}">
        <td>${pill(a.sev === "crit" ? "crit" : "warn", a.sev === "crit" ? "CRIT" : "WARN")}</td>
        <td class="mono small">${esc(a.where)}</td>
        <td>${esc(a.msg)}${a.flapping ? ` <span class="pill warn" title="Fired ${a.flaps + 1} times within 10 minutes">flapping</span>` : ""}</td>
        <td class="small nowrap" title="${esc(fmt.time(a.first_seen))}">${esc(fmt.short(a.first_seen))}</td>
        <td class="small">${fmt.dur(a.duration)}</td>
        <td>${a.status === "resolved" ? pill("ok", "resolved") : pill(a.sev === "crit" ? "crit" : "warn", "firing")}
          ${a.acked_by ? `<div class="sub">ack by ${esc(a.acked_by)}</div>` : ""}${a.muted ? `<div class="sub">muted until ${esc(fmt.short(a.muted_until))}</div>` : ""}</td>
        <td><div class="row op" style="flex-wrap:nowrap;justify-content:flex-end">${a.status === "firing" ? `
          ${a.kind === "cfg.drift" ? `<button class="btn sm pri" data-accept="${esc(a.where)}" title="Keep the file as it is now and stop alerting">Accept change</button>` : ""}
          <button class="btn sm" data-ack="${a.id}" data-v="${a.acked_by ? 0 : 1}">${a.acked_by ? "Unack" : "Ack"}</button>
          ${a.muted ? `<button class="btn sm" data-unmute="${esc(a.key)}">Unmute</button>`
            : `<select class="sm" data-mute="${esc(a.key)}"><option value="">Mute…</option><option value="30">30 min</option><option value="60">1 hour</option><option value="240">4 hours</option><option value="1440">24 hours</option><option value="10080">7 days</option></select>`}` : ""}</div></td></tr>`).join("")}
      </tbody></table>`
      : `<div class="empty ${f.tab === "active" ? "ok" : ""}">${f.tab === "active" ? "No active alerts — all clear." : "No alerts in this period."}</div>`;
    const ms = m.items;
    $("#alMutes").innerHTML = ms.length ? `<table><thead><tr><th>What</th><th>Until</th><th>By</th><th>Reason</th><th></th></tr></thead><tbody>
      ${ms.map((x) => `<tr><td class="mono small">${esc(x.match.startsWith("node:") ? "whole node " + x.match.slice(5) : x.match.split("|").slice(1).join(" · "))}</td>
        <td class="small">${esc(fmt.short(x.until))} <span class="sub">(${fmt.dur(x.until - Date.now() / 1000)} left)</span></td>
        <td>${esc(x.created_by || "")}</td><td class="small">${esc(x.reason || "")}</td>
        <td><button class="btn sm op" data-delmute="${x.id}">Remove</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">Nothing muted.</div>`;
  },

  async onClick(e) {
    const b = e.target.closest("button");
    if (!b) return;
    try {
      if (b.dataset.ack) {
        await api(`/api/alerts/${b.dataset.ack}/ack`, { body: { ack: b.dataset.v === "1" } });
      } else if (b.dataset.unmute) {
        const m = S.cache.mutes.find((x) => x.match === b.dataset.unmute);
        if (m) await api(`/api/mutes/${m.id}`, { method: "DELETE" });
      } else if (b.dataset.accept) {
        if (!(await confirmBox("Accept this change?", `<p>The file as it is now on the node becomes the known version. It's already saved in the config history (and in Edit config → History you can restore an older backup).</p>`, "Accept"))) return;
        await api("/api/alerts/drift/accept", { body: { where: b.dataset.accept } });
        await api("/api/alerts/check", { body: {} }).catch(() => {});
      } else if (b.dataset.delmute) {
        await api(`/api/mutes/${b.dataset.delmute}`, { method: "DELETE" });
      } else return;
      refresh(true); updateBadge();
    } catch (err) { toast(err.message, "bad"); }
  },

  async onChange(e) {
    const sel = e.target.closest("[data-mute]");
    if (!sel || !sel.value) return;
    try {
      await api("/api/mutes", { body: { match: sel.dataset.mute, minutes: +sel.value } });
      toast("Muted", "ok");
    } catch (err) { toast(err.message, "bad"); }
    refresh(true); updateBadge();
  },

  async muteNode() {
    const nodes = [...S.inv.haproxy.map((n) => n.name), ...S.inv.cloudflared.map((n) => n.name)];
    const changed = await taskModal({
      title: "Mute a node (maintenance)", submit: "Mute",
      html: `<label>Node<select name="node">${nodes.map((n) => `<option>${esc(n)}</option>`).join("")}</select></label>
        <label>For<select name="minutes"><option value="30">30 minutes</option><option value="60" selected>1 hour</option><option value="240">4 hours</option><option value="1440">24 hours</option><option value="10080">7 days</option></select></label>
        <label>Reason (optional)<input name="reason" type="text" placeholder="patching, reboot…" maxlength="200"></label>
        <div class="note">Alerts for this node are still recorded and shown, but no Telegram/Discord message is sent until the mute ends.</div>`,
      run: (fd) => api("/api/mutes", { body: { match: `node:${fd.node}`, minutes: +fd.minutes, reason: fd.reason } })
        .then(() => ({ ok: true, output: `${fd.node} muted.` })),
    });
    if (changed) { refresh(true); updateBadge(); }
  },
};
