/* Gateway Console web UI — Activity page: every change made through the console, newest first.
 * Search, filters (user, result, category, time range, hide sign-ins), rows grouped by day with the
 * full output under Details, "Load more" paging and CSV export. */
"use strict";

const ACT_CATS = [["", "All"], ["config", "Config changes"], ["server", "Server state"], ["tunnel", "Tunnels & DNS"], ["monitor", "Monitoring"],
  ["settings", "Users & settings"], ["updates", "Updates & backups"], ["signin", "Sign-ins"]];
const CAT_TAG = { config: "config", server: "server", tunnel: "tunnel", monitor: "monitoring", settings: "settings", updates: "update", signin: "sign-in", other: "other" };

PAGES.activity = {
  every: 30,
  f: { q: "", user: "", result: "", cat: "", range: "7d", hide_logins: true },
  mount(v) {
    setHeader("Activity", "Every change made through the console: who, what, result");
    const f = this.f;
    v.innerHTML = `<div class="panel"><div class="bd" style="display:flex;flex-direction:column;gap:12px">
        <div class="filters"><input type="search" id="acQ" placeholder="Search target, action or output…" value="${esc(f.q)}">
          <select id="acUser"><option value="">User: everyone</option></select>
          <select id="acRes"><option value="">Result: all</option><option value="ok">ok</option><option value="failed">failed</option></select>
          <span class="segs" id="acRange">${[["1d", "Today"], ["7d", "7 days"], ["30d", "30 days"], ["", "All"]].map(([k, l]) => `<button data-r="${k}" class="${k === f.range ? "on" : ""}">${l}</button>`).join("")}</span>
          <label class="check small" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="acHide" ${f.hide_logins ? "checked" : ""}> Hide sign-ins</label>
          <span class="grow"></span><a class="btn sm" id="acCsv" href="#">Export CSV</a></div>
        <div class="chipf" id="acCats">${ACT_CATS.map(([k, l]) => `<button data-c="${k}" class="${k === f.cat ? "on" : ""}">${l}</button>`).join("")}</div></div></div>
      <div class="panel"><div class="bd flush tbl-wrap" id="acList"><div class="empty">Loading…</div></div><div class="foot2" id="acFoot"></div></div>`;
    $("#acRes").value = f.result;
    let t;
    $("#acQ").addEventListener("input", (e) => { clearTimeout(t); t = setTimeout(() => { this.f.q = e.target.value.trim(); this.reload(); }, 300); });
    $("#acUser").addEventListener("change", (e) => { this.f.user = e.target.value; this.reload(); });
    $("#acRes").addEventListener("change", (e) => { this.f.result = e.target.value; this.reload(); });
    $("#acHide").addEventListener("change", (e) => { this.f.hide_logins = e.target.checked; this.reload(); });
    v.addEventListener("click", (e) => this.onClick(e));
  },
  params(offset, limit) {
    const f = this.f;
    const since = f.range ? Math.floor(Date.now() / 1000) - { "1d": 86400, "7d": 7 * 86400, "30d": 30 * 86400 }[f.range] : 0;
    const p = new URLSearchParams({ q: f.q, user: f.user, result: f.result, cat: f.cat, since, hide_logins: f.hide_logins, offset, limit });
    return p.toString();
  },
  reload() { this.items = null; refresh(true); },
  async load(_params, manual) {
    // auto-refresh only reloads the first page, so "Load more" pages stay put
    const n = manual || !this.items ? 50 : Math.max(50, this.items.length);
    const d = await api(`/api/audit?${this.params(0, n)}`);
    if (S.page !== "activity") return;
    this.items = d.items;
    this.render(d);
  },
  render(d) {
    const users = $("#acUser");
    const cur = this.f.user;
    users.innerHTML = `<option value="">User: everyone</option>` + d.users.map((u) => `<option ${u === cur ? "selected" : ""}>${esc(u)}</option>`).join("");
    $("#acCsv").href = `/api/audit.csv?${this.params(0, 100000)}`;
    let day = "";
    const rows = this.items.map((i, k) => {
      const dh = fmt.day(i.ts);
      const head = dh !== day ? `<tr class="dayh"><td colspan="7">${esc(dh === "Today" || dh === "Yesterday" ? `${dh} · ${fmt.date(i.ts)}` : dh)}</td></tr>` : "";
      day = dh;
      return `${head}<tr><td class="small nowrap">${esc(fmt.clock(i.ts))}</td><td>${esc(i.user)}</td>
        <td><span class="cat ${esc(i.cat)}">${esc(CAT_TAG[i.cat] || i.cat)}</span>${esc(i.action)}</td><td class="mono small">${esc(i.target)}</td>
        <td>${pill(i.ok ? "ok" : "crit", i.ok ? "ok" : "failed")}</td><td class="mono small muted">${esc(i.ip || "")}</td>
        <td>${i.detail ? `<button class="btn xs ghost" data-d="${k}">Details</button>` : ""}</td></tr>
        <tr class="det hidden" data-row="${k}"><td></td><td colspan="6"><pre class="detail">${esc(i.detail || "")}</pre></td></tr>`;
    }).join("");
    $("#acList").innerHTML = this.items.length ? `<table><thead><tr><th style="width:80px">Time</th><th>User</th><th>Action</th><th>Target</th><th>Result</th><th>From</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="empty">Nothing matches${this.f.q || this.f.user || this.f.result || this.f.cat ? " these filters" : " in this time range"}.</div>`;
    $("#acFoot").innerHTML = `<span>Showing ${fmt.n(this.items.length)} of ${fmt.n(d.matched)}${d.hidden_signins ? ` · ${fmt.plural(d.hidden_signins, "sign-in")} hidden` : ""}</span>
      ${d.more ? `<button class="btn sm" data-more>Load 50 more</button>` : ""}`;
  },
  async onClick(e) {
    const r = e.target.closest("#acRange button");
    if (r) { this.f.range = r.dataset.r; $$("#acRange button").forEach((b) => b.classList.toggle("on", b === r)); return this.reload(); }
    const c = e.target.closest("#acCats button");
    if (c) { this.f.cat = c.dataset.c; $$("#acCats button").forEach((b) => b.classList.toggle("on", b === c)); return this.reload(); }
    const dt = e.target.closest("[data-d]");
    if (dt) { const row = $(`[data-row="${dt.dataset.d}"]`); row.classList.toggle("hidden"); dt.textContent = row.classList.contains("hidden") ? "Details" : "Hide"; return; }
    const m = e.target.closest("[data-more]");
    if (m) {
      busy(m, true);
      try {
        const d = await api(`/api/audit?${this.params(this.items.length, 50)}`);
        this.items = this.items.concat(d.items);
        this.render({ ...d, matched: d.matched });
      } catch (err) { toast(err.message, "bad"); }
    }
  },
};
