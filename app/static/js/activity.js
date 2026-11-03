/* Gateway Console web UI — Activity page: the audit log of every change, newest first. */
"use strict";

PAGES.activity = {
  every: 30,
  mount(v) {
    setHeader("Activity", "Audit log of every change made through the console");
    v.innerHTML = `<div class="panel"><div class="bd flush tbl-wrap" id="audit"><div class="empty">Loading…</div></div></div>`;
    v.addEventListener("click", (e) => {
      const r = e.target.closest("[data-i]");
      if (r) { const it = S.cache.audit[+r.dataset.i]; modal({ title: `${it.action} · ${it.target}`, body: `<pre class="out">${esc(it.detail || "(no detail)")}</pre>` }); }
    });
  },
  async load() {
    const d = await api("/api/audit?n=300");
    if (S.page !== "activity") return;
    S.cache.audit = d.items;
    $("#audit").innerHTML = d.items.length ? `<table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Result</th><th>From</th></tr></thead><tbody>
      ${d.items.map((i, k) => `<tr data-i="${k}" style="cursor:pointer"><td class="small">${esc(fmt.time(i.ts))}</td><td>${esc(i.user)}</td><td>${esc(i.action)}</td><td class="mono small">${esc(i.target)}</td>
        <td>${pill(i.ok ? "ok" : "crit", i.ok ? "ok" : "failed")}</td><td class="mono small muted">${esc(i.ip)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">Nothing yet.</div>`;
  },
};

