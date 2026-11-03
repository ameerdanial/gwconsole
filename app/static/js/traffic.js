/* Gateway Console web UI — Traffic page: requests per site from Cloudflare (visitors, bandwidth,
 * cache, 4xx/5xx, countries) and per HAProxy frontend/backend (including internal and TCP traffic),
 * for today / 7 days / 30 days / 12 months, with a stacked chart and CSV export. */
"use strict";

PAGES.traffic = {
  every: 120,
  range: "7d",
  tab: "cf",
  mount(v, params) {
    if (params[0] === "haproxy") this.tab = "hp";
    setHeader("Traffic", "Requests per site (Cloudflare) and per frontend / backend (HAProxy)");
    v.innerHTML = `<div class="row" style="gap:10px;flex-wrap:wrap">
        <div class="ptab2" id="trTabs" style="border:0"><button data-t="cf">By site <em>Cloudflare</em></button><button data-t="hp">By frontend / backend <em>HAProxy</em></button></div>
        <span class="grow"></span>
        <span class="segs" id="trRange">${[["today", "Today"], ["7d", "7 days"], ["30d", "30 days"], ["12m", "12 months"]].map(([k, l]) => `<button data-r="${k}">${l}</button>`).join("")}</span>
        <button class="btn sm op" data-act="cfref" title="Fetch the newest numbers from Cloudflare now">Refresh from Cloudflare</button>
        <a class="btn sm" id="trCsv" href="#">Export CSV</a></div>
      <div id="trBody"><div class="panel"><div class="empty">Loading…</div></div></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
    this.marks();
  },
  marks() {
    $$("#trTabs button").forEach((b) => b.classList.toggle("on", b.dataset.t === this.tab));
    $$("#trRange button").forEach((b) => b.classList.toggle("on", b.dataset.r === this.range));
    $("#trCsv").href = `/api/traffic.csv?range=${this.range}&tab=${this.tab}`;
    $("[data-act=cfref]")?.classList.toggle("hidden", this.tab !== "cf");
  },
  async load() {
    const d = await api(`/api/traffic?range=${this.range}`);
    if (S.page !== "traffic") return;
    S.cache.traffic = d;
    this.render(d);
  },
  prevLabel() { return { today: "yesterday", "7d": "previous 7 days", "30d": "previous 30 days", "12m": "previous 12 months" }[this.range]; },
  delta(x, invert) {
    if (x?.delta == null) return `<span class="muted">no earlier data</span>`;
    const up = x.delta >= 0, good = invert ? !up : up;
    return `<span class="${good ? "up" : "down"}">${up ? "▲" : "▼"} ${Math.abs(x.delta)}%</span> vs ${this.prevLabel()}`;
  },
  kpi(l, v, d) { return `<div class="kpi"><div class="l">${l}</div><div class="v">${v}</div><div class="d">${d}</div></div>`; },
  xFmt(l) {
    if (this.range === "today") return l;
    if (this.range === "12m") return new Date(l + "-01T00:00:00").toLocaleDateString([], { month: "short" });
    return new Date(l + "T00:00:00").toLocaleDateString([], this.range === "7d" ? { weekday: "short", day: "numeric" } : { day: "numeric", month: "short" });
  },
  render(d) {
    const b = $("#trBody");
    const t = this.tab === "cf" ? d.cf : d.hp;
    const span = `${new Date(d.days[0] + "T00:00:00").toLocaleDateString([], { day: "numeric", month: "short" })} – ${new Date(d.days[1] + "T00:00:00").toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" })}`;
    if (this.tab === "cf") {
      const st = t.status || {};
      const errs = Object.entries(st.errors || {});
      let note = "";
      if (!t.accounts) note = `No Cloudflare account yet${S.role === "superadmin" ? ` — <a href="#/settings/cloudflare">add one in Settings</a>` : ""}. HAProxy numbers are on the other tab.`;
      else if (errs.length) note = errs.map(([a, e]) => `${pill("warn", a)} <span class="muted">${esc(e)}</span>`).join("<br>")
        + `<div class="sub" style="margin-top:6px">The API token needs <b>Zone → Analytics → Read</b> (Settings → Cloudflare → edit the account).</div>`;
      else if (!st.at) note = "Fetching numbers from Cloudflare for the first time — they appear within a few minutes.";
      const k = t.kpi;
      b.innerHTML = `${note ? `<div class="panel"><div class="bd small">${note}</div></div>` : ""}
        <div class="kpis">
          ${this.kpi("Requests", fmt.k(k.requests.value), this.delta(k.requests))}
          ${this.kpi("Unique visitors", fmt.k(k.visitors.value), this.delta(k.visitors))}
          ${this.kpi("Bandwidth", fmt.bytes(k.bytes.value), this.delta(k.bytes))}
          ${this.kpi("Served from Cloudflare cache", fmt.pct(k.cached.value), k.cached.delta == null ? `<span class="muted">share of requests</span>` : `${k.cached.delta >= 0 ? "+" : ""}${k.cached.delta} points vs ${this.prevLabel()}`)}
          ${this.kpi("Threats blocked", fmt.n(k.threats.value), this.delta(k.threats, true))}
        </div>
        <div class="panel"><div class="hd"><h2>Requests ${this.range === "today" ? "per hour" : this.range === "12m" ? "per month" : "per day"}</h2><span class="meta">${span} · top 3 sites + other</span></div><div class="chart" id="trChart"></div></div>
        <div class="panel"><div class="hd"><h2>Sites</h2><span class="meta">${t.hosts.length} hostname${t.hosts.length === 1 ? "" : "s"} · numbers from Cloudflare, so only traffic through Cloudflare</span></div>
          <div class="bd flush tbl-wrap">${t.hosts.length ? `<table><thead><tr><th>Site</th><th class="num">Requests</th><th class="num">Visits</th><th class="num">Bandwidth</th><th class="num">Cached</th><th class="num">4xx</th><th class="num">5xx</th><th>Top countries</th><th>Trend</th></tr></thead><tbody>
          ${t.hosts.map((h) => `<tr><td><b class="mono">${esc(h.name)}</b></td><td class="num">${fmt.n(h.requests)}</td><td class="num">${fmt.n(h.visitors)}</td>
            <td class="num">${fmt.bytes(h.bytes)}</td><td class="num">${h.requests ? fmt.pct((h.cached * 100) / h.requests, 0) : "–"}</td>
            <td class="num">${fmt.n(h.s4xx)}</td><td class="num" style="${h.requests && h.s5xx / h.requests > 0.01 ? "color:var(--crit)" : ""}">${fmt.n(h.s5xx)}</td>
            <td>${h.countries.map((c) => `<span class="colo">${esc(c)}</span>`).join("") || "–"}</td><td>${Charts.spark(h.series, { max: Math.max(...h.series, 1) })}</td></tr>`).join("")}
          </tbody></table>` : `<div class="empty">No Cloudflare traffic recorded for this range yet.</div>`}</div></div>`;
    } else {
      const k = t.kpi;
      const table = (rows, label) => rows.length ? `<table><thead><tr><th>${label}</th><th class="num">Requests</th><th class="num">Data</th><th class="num">4xx</th><th class="num">5xx</th><th class="num">5xx share</th><th>Busiest hour</th><th>Trend</th></tr></thead><tbody>
        ${rows.map((g) => {
          const [node, name] = g.name.split(/\/(?:fe|be):/);
          const share = g.requests ? (g.s5xx * 100) / g.requests : 0;
          return `<tr><td><b>${esc(name)}</b> <span class="sub">${esc(node)}</span></td><td class="num">${fmt.n(g.requests)}</td><td class="num">${fmt.bytes(g.bytes)}</td>
            <td class="num">${fmt.n(g.s4xx)}</td><td class="num">${fmt.n(g.s5xx)}</td><td class="num" style="${share > 1 ? "color:var(--crit)" : ""}">${g.requests ? fmt.pct(share, 2) : "–"}</td>
            <td>${g.busiest == null ? "–" : `${String(g.busiest).padStart(2, "0")}:00`}</td><td>${Charts.spark(g.series, { max: Math.max(...g.series, 1) })}</td></tr>`;
        }).join("")}</tbody></table>` : `<div class="empty">Nothing recorded yet — HAProxy numbers build up from the moment v1.4 runs.</div>`;
      b.innerHTML = `<div class="kpis">
          ${this.kpi("Requests (frontends)", fmt.k(k.requests.value), this.delta(k.requests))}
          ${this.kpi("Data in + out", fmt.bytes(k.bytes.value), this.delta(k.bytes))}
          ${this.kpi("5xx share (backends)", k.err5xx.value == null ? "–" : fmt.pct(k.err5xx.value, 2), "of backend responses")}
          ${this.kpi("Peak connections", k.peak_conns.value == null ? "–" : fmt.n(k.peak_conns.value), "highest in the last 2 days")}
        </div>
        <div class="panel"><div class="hd"><h2>Requests ${this.range === "today" ? "per hour" : this.range === "12m" ? "per month" : "per day"}</h2><span class="meta">${span} · top 3 frontends + other · includes internal and TCP traffic</span></div><div class="chart" id="trChart"></div></div>
        <div class="panel"><div class="hd"><h2>Frontends</h2><span class="meta">TCP frontends count connections</span></div><div class="bd flush tbl-wrap">${table(t.frontends, "Frontend")}</div></div>
        <div class="panel"><div class="hd"><h2>Backends</h2></div><div class="bd flush tbl-wrap">${table(t.backends, "Backend")}</div></div>`;
    }
    const series = t.chart.series.map((s) => ({ ...s, name: s.name.replace(/\/(fe|be):/, " / ") }));
    Charts.bars($("#trChart"), t.chart.labels, series, { xFmt: (l) => this.xFmt(l), tipFmt: (l) => this.xFmt(l) });
  },
  async onClick(e) {
    const tb = e.target.closest("#trTabs button");
    if (tb) { this.tab = tb.dataset.t; this.marks(); if (S.cache.traffic) this.render(S.cache.traffic); return; }
    const rb = e.target.closest("#trRange button");
    if (rb) { this.range = rb.dataset.r; this.marks(); return refresh(true); }
    const b = e.target.closest("[data-act=cfref]");
    if (b) {
      busy(b, true);
      try { const r = await api("/api/traffic/refresh", { body: {} }); const errs = Object.values(r.status?.errors || {}); errs.length ? toast(errs[0], "bad") : toast("Updated from Cloudflare", "ok"); refresh(); }
      catch (err) { toast(err.message, "bad"); } finally { busy(b, false); }
    }
  },
};
