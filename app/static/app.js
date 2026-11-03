/* Gateway Console — vanilla JS front-end */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------------------------------------------------------------- api
class AuthError extends Error {}
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-GWC": "1" }, credentials: "same-origin" };
  if (opts.body !== undefined) { init.method = opts.method || "POST"; init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  const r = await fetch(path, init);
  let j = null;
  try { j = await r.json(); } catch { /* non-json */ }
  if (r.status === 401 && path !== "/api/login") { showLogin(); throw new AuthError("not logged in"); }
  if (!r.ok) throw new Error((j && j.error) || `HTTP ${r.status}`);
  return j;
}

// ---------------------------------------------------------------- format
const fmt = {
  n: (v) => (v == null ? "–" : Number(v).toLocaleString()),
  bytes(v) {
    if (v == null) return "–";
    const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; v = Number(v);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
  },
  dur(s) {
    if (s == null || s === "") return "–";
    s = Number(s); const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return `${d}d ${h}h`; if (h) return `${h}h ${m}m`; if (m) return `${m}m`; return `${s}s`;
  },
  ago(t) {
    if (!t) return "–";
    const ms = typeof t === "number" ? t * 1000 : Date.parse(t);
    if (isNaN(ms)) return esc(t);
    return fmt.dur(Math.max(0, Math.round((Date.now() - ms) / 1000))) + " ago";
  },
  time: (ts) => new Date(ts * 1000).toLocaleString(),
};

function srvClass(status) {
  status = status || "";
  if (status.startsWith("UP") || status === "OPEN" || status === "no check") return "ok";
  if (status.includes("MAINT")) return "mute";
  if (status === "DRAIN" || status.startsWith("NOLB") || status.includes("going")) return "warn";
  if (status.startsWith("DOWN")) return "crit";
  return "mute";
}
function svcClass(a) { return a === "active" ? "ok" : a === "activating" || a === "reloading" ? "warn" : "crit"; }
function edgeClass(s) { return s === "healthy" ? "ok" : s === "degraded" ? "warn" : s ? "crit" : "mute"; }
function dnsClass(s) { return s === "ok" ? "ok" : s === "not_proxied" || s === "no_zone" ? "warn" : "crit"; }
const pill = (cls, txt) => `<span class="pill ${cls}">${esc(txt)}</span>`;

// ---------------------------------------------------------------- ui helpers
function toast(msg, kind = "") {
  const t = document.createElement("div");
  t.className = `toast ${kind}`; t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), kind === "bad" ? 9000 : 4500);
}

function modal({ title, body, actions = [], size = "", onOpen }) {
  return new Promise((resolve) => {
    const bg = document.createElement("div");
    bg.className = "modal-bg";
    bg.innerHTML = `<div class="modal ${size}"><div class="hd"><h3>${esc(title)}</h3><div class="grow"></div>
      <button class="btn ghost sm" data-x>✕</button></div><div class="bd"></div>
      ${actions.length ? `<div class="ft">${actions.map((a, i) => `<button class="btn ${a.cls || ""}" data-i="${i}">${esc(a.label)}</button>`).join("")}</div>` : ""}</div>`;
    const bd = $(".bd", bg);
    if (typeof body === "string") bd.innerHTML = body; else if (body) bd.appendChild(body);
    const close = (v) => { bg.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape") close(null); };
    document.addEventListener("keydown", onKey);
    bg.addEventListener("click", (e) => {
      if (e.target === bg || e.target.closest("[data-x]")) return close(null);
      const b = e.target.closest("[data-i]");
      if (b) close(actions[+b.dataset.i].value);
    });
    document.body.appendChild(bg);
    bg._body = bd; bg._close = close;
    if (onOpen) onOpen(bg);
  });
}
const confirmBox = (title, html, label = "Confirm", cls = "pri") =>
  modal({ title, body: html, size: "sm", actions: [{ label: "Cancel", value: false }, { label, cls, value: true }] });

function busy(btn, on) { if (!btn) return; btn.disabled = on; if (on) { btn._t = btn.textContent; btn.textContent = "…"; } else if (btn._t) btn.textContent = btn._t; }

function renderDiff(d) {
  if (!d) return `<div class="empty">No differences.</div>`;
  return `<pre class="diff">${d.replace(/\n$/, "").split("\n").map((l) => {
    const c = l.startsWith("+++") || l.startsWith("---") ? "f" : l.startsWith("@@") ? "h" : l.startsWith("+") ? "a" : l.startsWith("-") ? "d" : "";
    return `<span class="${c}">${esc(l) || " "}</span>`;
  }).join("")}</pre>`;
}

async function showLogs(title, loader, sources) {
  const wrap = document.createElement("div");
  wrap.innerHTML = `<div class="row">
      ${sources ? `<div class="seg" data-src>${sources.map((s, i) => `<button class="${i ? "" : "on"}" data-s="${s[0]}">${s[1]}</button>`).join("")}</div>` : ""}
      <select data-lines><option>100</option><option selected>200</option><option>500</option><option>1000</option></select>
      <button class="btn sm" data-reload>Refresh</button><span class="muted small" data-st></span></div>
    <div class="out" style="max-height:62vh"><pre class="log" data-log>Loading…</pre></div>`;
  let src = sources ? sources[0][0] : null;
  const load = async () => {
    $("[data-st]", wrap).textContent = "loading…";
    try {
      const r = await loader(src, $("[data-lines]", wrap).value);
      $("[data-log]", wrap).textContent = r.text || "(empty)";
      const box = $(".out", wrap); box.scrollTop = box.scrollHeight;
      $("[data-st]", wrap).textContent = "";
    } catch (e) { $("[data-log]", wrap).textContent = e.message; }
  };
  wrap.addEventListener("click", (e) => {
    const s = e.target.closest("[data-s]");
    if (s) { src = s.dataset.s; $$("[data-s]", wrap).forEach((b) => b.classList.toggle("on", b === s)); load(); }
    if (e.target.closest("[data-reload]")) load();
  });
  $("[data-lines]", wrap).addEventListener("change", load);
  load();
  await modal({ title, body: wrap });
}

// form modal that stays open while the task runs, then shows the step-by-step result
function taskModal({ title, html, submit, cls = "pri", run, size = "sm" }) {
  const f = document.createElement("form");
  f.className = "form";
  f.innerHTML = `${html}<div class="ferr" data-err></div><pre class="out hidden" data-res></pre>
    <div class="row" style="justify-content:flex-end"><button type="button" class="btn" data-cancel>Cancel</button><button type="submit" class="btn ${cls}" data-submit>${esc(submit)}</button></div>`;
  let close = () => {}, done = false, changed = false;
  f.addEventListener("click", (e) => { if (e.target.closest("[data-cancel]")) close(); });
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (done) return close();
    const btn = $("[data-submit]", f), err = $("[data-err]", f), res = $("[data-res]", f);
    const fd = Object.fromEntries([...new FormData(f).entries()]);
    $$("input[type=checkbox]", f).forEach((c) => (fd[c.name] = c.checked && !c.disabled));
    err.textContent = ""; btn.disabled = true; btn.textContent = "Working…";
    const wasDisabled = $$("input,select,textarea", f).filter((x) => x.disabled);
    $$("input,select,textarea", f).forEach((x) => (x.disabled = true));
    try {
      const r = await run(fd, f);
      changed = true;
      res.textContent = r.output || (r.ok ? "Done." : "Failed.");
      res.classList.remove("hidden"); res.classList.toggle("ok", !!r.ok); res.classList.toggle("bad", !r.ok);
      done = true; btn.disabled = false; btn.textContent = "Close"; btn.className = "btn";
      $("[data-cancel]", f).classList.add("hidden");
    } catch (ex) {
      if (ex instanceof AuthError) return;
      err.textContent = ex.message; btn.disabled = false; btn.textContent = submit;
      $$("input,select,textarea", f).forEach((x) => (x.disabled = wasDisabled.includes(x)));
    }
  });
  return modal({ title, body: f, size, onOpen: (bg) => {
    close = () => bg._close(changed);
    setTimeout(() => $("input:not([type=checkbox]),select", f)?.focus(), 30);
  } });
}

function showOutput(title, r) {
  return modal({ title, size: "", body: `<div class="row">${pill(r.ok ? "ok" : "crit", r.ok ? "success" : r.stage || "failed")}</div>
    <pre class="out ${r.ok ? "ok" : "bad"}">${esc(r.output || "(no output)")}</pre>`, actions: [{ label: "Close", value: true }] });
}

// ---------------------------------------------------------------- app state
const S = { user: null, page: "overview", params: [], timer: null, inv: null, cache: {}, editor: null };

function setHeader(title, sub = "") { $("#title").textContent = title; $("#subtitle").textContent = sub; }
function setPulse(state) { const p = $("#pulse"); p.className = "pulse " + (state || ""); }
function stamp() { $("#updated").textContent = "updated " + new Date().toLocaleTimeString(); }

function showLogin() {
  clearInterval(S.timer);
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#loginForm [name=user]").focus();
}

async function boot() {
  let me;
  try {
    me = await api("/api/me");
    S.user = me.user;
  } catch (e) { if (!(e instanceof AuthError)) toast(e.message, "bad"); return; }
  $("#who").textContent = S.user;
  $("#ver").textContent = me.version ? `v${me.version}` : "";
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  S.inv = await api("/api/inventory");
  route();
}

$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  $("#loginErr").textContent = "";
  try {
    await api("/api/login", { body: { user: f.get("user"), password: f.get("password") } });
    e.target.reset();
    boot();
  } catch (err) { $("#loginErr").textContent = err.message; }
});
$("#logout").addEventListener("click", async () => { await api("/api/logout", { body: {} }).catch(() => {}); showLogin(); });
$("#refresh").addEventListener("click", () => refresh(true));
$("#auto").addEventListener("change", () => schedule());

// ---------------------------------------------------------------- router
const PAGES = {};
window.addEventListener("hashchange", () => {
  if (S.page === "config" && S.editor && S.editor.dirty && !location.hash.startsWith("#/config")) {
    if (!window.confirm("You have unapplied config edits. Leave this page?")) { history.back(); return; }
  }
  route();
});
window.addEventListener("beforeunload", (e) => { if (S.editor && S.editor.dirty) { e.preventDefault(); e.returnValue = ""; } });

function route() {
  const parts = (location.hash.replace(/^#\/?/, "") || "overview").split("/").map(decodeURIComponent);
  const page = PAGES[parts[0]] ? parts[0] : "overview";
  const same = page === S.page && $("#view").dataset.page === page && JSON.stringify(parts.slice(1)) === JSON.stringify(S.params);
  S.page = page; S.params = parts.slice(1);
  $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.p === page));
  if (!same) {
    const fresh = $("#view").cloneNode(false); // drop old listeners
    $("#view").replaceWith(fresh);
    fresh.dataset.page = page;
    if (page !== "config") S.editor = null;
    PAGES[page].mount($("#view"), S.params);
  }
  refresh(true);
}

async function refresh(manual) {
  const p = PAGES[S.page];
  clearTimeout(S.timer);
  if (p.load) {
    setPulse("busy");
    try { await p.load(S.params, manual); setPulse(""); stamp(); }
    catch (e) { if (!(e instanceof AuthError)) { setPulse("err"); if (manual) toast(e.message, "bad"); } }
  }
  schedule();
}
function schedule() {
  clearTimeout(S.timer);
  const p = PAGES[S.page];
  if ($("#auto").checked && p.every) S.timer = setTimeout(() => refresh(false), p.every * 1000);
}

function alertBadge(alerts) {
  const b = $("#alertCount");
  const crit = alerts.filter((a) => a.sev === "crit").length;
  b.classList.toggle("hidden", !alerts.length);
  b.classList.toggle("warn", !crit);
  b.textContent = alerts.length;
}

// ================================================================ OVERVIEW
PAGES.overview = {
  every: 10,
  mount(v) {
    setHeader("Overview", "All gateways at a glance");
    v.innerHTML = `<div class="kpis" id="kpis"></div>
      <div class="panel"><div class="hd"><h2>Alerts</h2><span class="meta" id="alertMeta"></span></div><div class="bd flush" id="alerts"><div class="empty">Loading…</div></div></div>
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
    const crit = d.alerts.filter((a) => a.sev === "crit").length;
    $("#kpis").innerHTML =
      tile("HAProxy nodes up", k.haproxy_up, k.haproxy_total, lvl(k.haproxy_up, k.haproxy_total)) +
      tile("Backend servers up", k.servers_up, k.servers_total, lvl(k.servers_up, k.servers_total)) +
      tile("Tunnels healthy", k.tunnels_ok, k.tunnels_total, lvl(k.tunnels_ok, k.tunnels_total)) +
      tile("Current connections", fmt.n(k.conns), null, "") +
      `<div class="kpi ${crit ? "crit" : d.alerts.length ? "warn" : ""}"><div class="l">Open alerts</div><div class="v">${d.alerts.length}${crit ? ` <small>${crit} critical</small>` : ""}</div><div class="bar" style="width:100%"></div></div>`;
    alertBadge(d.alerts);
    $("#alertMeta").textContent = d.alerts.length ? `${d.alerts.length} issue(s)` : "";
    $("#alerts").innerHTML = d.alerts.length
      ? `<ul class="alerts">${d.alerts.map((a) => `<li>${pill(a.sev === "crit" ? "crit" : "warn", a.sev === "crit" ? "CRIT" : "WARN")}<span class="w">${esc(a.where)}</span><span class="m">${esc(a.msg)}</span></li>`).join("")}</ul>`
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

// ================================================================ HAPROXY
PAGES.haproxy = {
  every: 5,
  mount(v, params) {
    const nodes = S.inv.haproxy;
    const cur = params[0] || nodes[0]?.name;
    S.cache.hpNode = cur;
    setHeader("HAProxy", "Live runtime stats · server state · service control");
    if (!nodes.length) { v.innerHTML = `<div class="panel"><div class="empty">No HAProxy nodes in config.yaml.</div></div>`; return; }
    v.innerHTML = `<div class="row">${nodes.length > 1 ? `<div class="seg">${nodes.map((n) => `<button class="${n.name === cur ? "on" : ""}" data-node="${esc(n.name)}">${esc(n.name)}${n.site ? ` · ${esc(n.site)}` : ""}</button>`).join("")}</div>` : ""}
        <div class="grow"></div><input type="search" id="hpFilter" placeholder="Filter backends / servers…" value="${esc(S.cache.hpFilter || "")}"></div>
      <div class="panel" id="hpHead"><div class="empty">Loading…</div></div>
      <div class="panel"><div class="hd"><h2>Frontends</h2></div><div class="bd flush tbl-wrap" id="hpFe"></div></div>
      <div class="panel"><div class="hd"><h2>Backends & servers</h2><span class="meta">State changes are runtime-only (lost on restart). Use Config to make them permanent.</span></div><div class="bd flush tbl-wrap" id="hpBe"></div></div>`;
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
        <div class="acts"><button class="btn sm" data-act="logs">Logs</button><a class="btn sm" href="#/config/haproxy/${encodeURIComponent(d.node)}">Edit config</a>
        <button class="btn sm" data-act="svc" data-a="reload">Reload</button><button class="btn sm danger" data-act="svc" data-a="restart">Restart</button></div></div>
      <div class="bd"><dl class="kv" style="grid-template-columns:repeat(auto-fit,minmax(110px,auto) minmax(120px,1fr))">
        <dt>Version</dt><dd>${esc(i.Version || "–")}</dd><dt>Uptime</dt><dd>${fmt.dur(i.Uptime_sec)}</dd>
        <dt>Connections</dt><dd>${fmt.n(i.CurrConns)} / ${fmt.n(i.Maxconn)}</dd><dt>Conn rate</dt><dd>${fmt.n(i.ConnRate)}/s</dd>
        <dt>Sess rate</dt><dd>${fmt.n(i.SessRate)}/s</dd><dt>Total req</dt><dd>${fmt.n(i.CumReq)}</dd>
        <dt>Threads</dt><dd>${esc(i.Nbthread || "–")}</dd><dt>Idle</dt><dd>${i.Idle_pct != null ? esc(i.Idle_pct) + "%" : "–"}</dd>
        <dt>Service since</dt><dd>${esc(d.service.since || "–")}</dd></dl>
        ${d.stats_error ? `<div class="out bad" style="margin-top:12px">${esc(d.stats_error)}</div>` : ""}</div>`;
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
            <td><div class="seg">${["ready", "drain", "maint"].map((x) => `<button class="${x} ${st === x ? "on" : ""}" data-act="srv" data-be="${esc(b.name)}" data-srv="${esc(s.name)}" data-st="${x}">${x}</button>`).join("")}</div></td></tr>`;
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

// ================================================================ TUNNELS
const SERVICE_HINT = `<div class="hint">e.g. <code>http://10.10.10.20:80</code> · <code>https://10.10.10.20:443</code> · <code>tcp://10.10.10.20:25565</code> · <code>ssh://10.10.10.20:22</code></div>`;

PAGES.tunnels = {
  every: 15,
  mount(v) {
    setHeader("Tunnels", "cloudflared services · Cloudflare edge · ingress & DNS routes");
    v.innerHTML = `<div id="tunAcc"></div><div id="tunNodes"><div class="panel"><div class="empty">Loading…</div></div></div><div id="tunUnmanaged"></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
  },
  async load() {
    const d = await api("/api/tunnels");
    if (S.page !== "tunnels") return;
    S.cache.tun = d;
    const accErr = Object.entries(d.accounts).filter(([, a]) => a.error);
    $("#tunAcc").innerHTML = accErr.length ? `<div class="panel"><div class="bd">${accErr.map(([n, a]) => `<div>${pill("warn", "CF API")} <b>${esc(n)}</b> <span class="muted">${esc(a.error)}</span></div>`).join("")}</div></div>` : "";
    $("#tunNodes").innerHTML = d.nodes.map((n) => {
      if (n.error) return `<div class="panel"><div class="hd"><h2>${esc(n.node)}</h2>${pill("crit", "unreachable")}</div><div class="bd muted">${esc(n.error)}</div></div>`;
      return `<div class="panel"><div class="hd"><h2>${esc(n.node)}</h2><span class="meta mono">${esc(n.host)}</span>${n.site ? `<span class="tag">${esc(n.site)}</span>` : ""}<span class="meta">${esc(n.version)}</span>
          <div class="acts"><button class="btn sm pri" data-act="new" data-node="${esc(n.node)}">+ New tunnel</button></div></div>
        <div class="bd" style="display:flex;flex-direction:column;gap:14px">${n.tunnels.map((t) => this.tunnel(n, t)).join("") || `<div class="empty">No cloudflared services found on this node.</div>`}</div></div>`;
    }).join("") || `<div class="panel"><div class="empty">No cloudflared nodes in config.yaml.</div></div>`;
    const um = d.unmanaged || [];
    $("#tunUnmanaged").innerHTML = um.length ? `<div class="panel"><div class="hd"><h2>In Cloudflare, not on a managed node</h2>
        <span class="meta">Tunnels in your accounts that no managed cloudflared runs. Live ones run somewhere else (another server / site).</span></div>
      <div class="bd flush tbl-wrap"><table><thead><tr><th>Account</th><th>Tunnel</th><th>Status</th><th>Connections</th><th>Created</th><th></th></tr></thead><tbody>
      ${um.map((t) => {
        const ips = [...new Set(t.connections.map((c) => c.origin_ip).filter(Boolean))];
        return `<tr><td>${esc(t.account)}</td><td><b>${esc(t.name)}</b><div class="sub mono">${esc(t.id)}</div></td><td>${pill(edgeClass(t.status), t.status)}</td>
          <td>${t.connections.length ? `${t.connections.length} from <span class="mono small">${esc(ips.join(", "))}</span>` : `<span class="muted">none</span>`}</td>
          <td class="small">${esc((t.created_at || "").slice(0, 10))}</td>
          <td>${t.connections.length ? `<span class="sub">running elsewhere</span>` : `<button class="btn sm danger" data-act="cfdel" data-acc="${esc(t.account)}" data-id="${esc(t.id)}" data-name="${esc(t.name)}">Delete</button>`}</td></tr>`;
      }).join("")}</tbody></table></div></div>` : "";
  },
  find(node, name) {
    const n = S.cache.tun.nodes.find((x) => x.node === node);
    return { n, t: n?.tunnels.find((x) => x.name === name) };
  },
  tunnel(n, t) {
    const e = t.edge, ref = `${encodeURIComponent(n.node)}/${encodeURIComponent(t.name)}`;
    const routes = Object.fromEntries((t.dns?.routes || []).map((r) => [r.hostname, r]));
    const ing = t.config.ingress;
    const local = !t.remote;
    return `<div class="card" style="gap:12px">
      <div class="t" style="flex-wrap:wrap">${esc(t.name)} <span class="muted mono small">${esc(t.unit)}</span>${t.remote ? pill("info", "token-run") : ""}
        <span class="r row">${pill(svcClass(t.service.active), "local: " + t.service.active)} ${e ? pill(edgeClass(e.status), "edge: " + e.status) : pill("mute", t.edge_error ? "edge: API error" : "edge: not found")}</span></div>
      <div class="row small">
        ${local ? `<button class="btn sm pri" data-act="addhost" data-ref="${ref}">+ Hostname</button>
        <button class="btn sm" data-act="test" data-ref="${ref}">Test rule</button>
        <a class="btn sm" href="#/config/tunnel/${encodeURIComponent(n.node + ":" + t.name)}">Edit config</a>` : ""}
        <button class="btn sm" data-act="logs" data-ref="${ref}">Logs</button>
        <span class="grow"></span>
        ${t.service.active === "active" ? `<button class="btn sm" data-act="svc" data-a="restart" data-ref="${ref}">Restart</button><button class="btn sm" data-act="svc" data-a="stop" data-ref="${ref}">Stop</button>`
          : `<button class="btn sm pri" data-act="svc" data-a="start" data-ref="${ref}">Start</button>`}
        <button class="btn sm danger" data-act="del" data-ref="${ref}">Delete</button>
      </div>
      <dl class="kv"><dt>Tunnel</dt><dd class="mono">${esc((e && e.id) || t.config.tunnel || "–")}${e && t.config.tunnel && e.id !== t.config.tunnel ? ` <span class="muted">(${esc(t.config.tunnel)})</span>` : ""}</dd>
        <dt>Account</dt><dd>${t.cf_account ? esc(t.cf_account) + (t.cf_account_auto ? ` <span class="sub">(auto-matched)</span>` : "") : `<span class="muted">not found in configured accounts</span>`}</dd>
        ${local ? `<dt>Config</dt><dd class="mono">${esc(t.config_path)}</dd>` : ""}
        <dt>Running since</dt><dd>${esc(t.service.since || "–")}${t.service.restarts ? ` · ${t.service.restarts} restarts` : ""}</dd>
        ${t.ready_connections != null ? `<dt>Ready conns</dt><dd>${t.ready_connections} (metrics)</dd>` : ""}
        ${e ? `<dt>Edge conns</dt><dd>${e.connections.map((c) => `<span class="chip" title="${esc(c.origin_ip + " · " + c.version + " · opened " + c.opened_at)}">${esc(c.colo)}</span>`).join("") || "none"}
          ${e.connections[0] ? `<span class="sub">v${esc(e.connections[0].version)} from ${esc(e.connections[0].origin_ip)}</span>` : ""}</dd>` : ""}
        ${t.config.error ? `<dt>Config</dt><dd style="color:var(--crit)">${esc(t.config.error)}</dd>` : ""}</dl>
      ${local ? `<div class="tbl-wrap" style="border:1px solid var(--line);border-radius:8px"><table><thead><tr><th>#</th><th>Hostname</th><th>Service</th><th>DNS route</th><th></th></tr></thead><tbody>
        ${ing.map((r, i) => {
          const dr = routes[r.hostname];
          const canFix = dr && ["missing", "not_proxied", "other_tunnel"].includes(dr.status);
          return `<tr class="${r.hostname ? "" : "dim"}"><td class="sub">${i + 1}</td><td class="mono">${r.hostname ? esc(r.hostname) : "<i>catch-all</i>"}${r.path ? `<div class="sub">path ${esc(r.path)}</div>` : ""}</td>
            <td class="mono small">${esc(r.service)}${Object.keys(r.origin || {}).length ? `<div class="sub">${esc(Object.entries(r.origin).map(([k, v]) => k + "=" + JSON.stringify(v)).join(" "))}</div>` : ""}</td>
            <td>${!r.hostname ? "" : dr ? `${pill(dnsClass(dr.status), dr.status.replace("_", " "))} <span class="sub">${esc(dr.detail)}</span>` : t.dns?.error ? `<span class="sub">${esc(t.dns.error)}</span>` : `<span class="sub">–</span>`}</td>
            <td><div class="row" style="justify-content:flex-end;flex-wrap:nowrap">${canFix ? `<button class="btn sm" data-act="dns" data-ref="${ref}" data-host="${esc(r.hostname)}">${dr.status === "missing" ? "Create route" : "Fix route"}</button>` : ""}
              ${r.hostname ? `<button class="btn sm ghost" title="Remove hostname" data-act="rmhost" data-ref="${ref}" data-host="${esc(r.hostname)}" data-path="${esc(r.path || "")}" data-dns="${dr && dr.status !== "missing" && dr.status !== "other_tunnel" && dr.status !== "conflict" ? 1 : ""}">Remove</button>` : ""}</div></td></tr>`;
        }).join("") || `<tr><td colspan="5" class="empty">No ingress rules.</td></tr>`}
      </tbody></table></div>
      ${t.dns?.orphans?.length ? `<div class="small">${pill("warn", "orphan DNS")} <span class="muted">These records point at this tunnel but have no ingress rule (they'll hit the catch-all):</span> ${t.dns.orphans.map((o) => `<span class="chip">${esc(o)}</span>`).join("")}</div>` : ""}`
      : `<div class="muted small">Token-run tunnel: its public hostnames are managed in the Cloudflare Zero Trust dashboard, not in a local config.yml. You can still start/stop/restart, read logs or delete it here.</div>`}
    </div>`;
  },
  async after(changed) {
    if (!changed) return;
    try { S.inv = await api("/api/inventory"); } catch { /* ignore */ }
    refresh();
  },
  async onClick(e) {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act;
    if (act === "new") return this.newTunnel(b.dataset.node);
    if (act === "cfdel") return this.cfDelete(b.dataset);
    const ref = b.dataset.ref, [node, name] = ref.split("/").map(decodeURIComponent);
    if (act === "logs") return showLogs(`cloudflared logs · ${name}`, (_, n) => api(`/api/tunnels/${ref}/logs?lines=${n}`));
    if (act === "addhost") return this.addHost(ref, name);
    if (act === "rmhost") return this.rmHost(ref, name, b.dataset);
    if (act === "del") return this.delTunnel(ref, node, name);
    if (act === "test") {
      const w = document.createElement("div");
      w.innerHTML = `<p class="muted small" style="margin:0">Shows which ingress rule <code>cloudflared tunnel ingress rule</code> matches for a URL.</p>
        <div class="row"><input type="text" class="grow" placeholder="https://app.adproject.fun/path" data-url><button class="btn pri" data-go>Test</button></div><pre class="out hidden" data-res></pre>`;
      const go = async () => {
        const res = $("[data-res]", w); res.classList.remove("hidden", "ok", "bad"); res.textContent = "…";
        try { const r = await api(`/api/tunnels/${ref}/test`, { body: { url: $("[data-url]", w).value.trim() } }); res.textContent = r.output; res.classList.add(r.ok ? "ok" : "bad"); }
        catch (err) { res.textContent = err.message; res.classList.add("bad"); }
      };
      w.addEventListener("click", (ev) => ev.target.closest("[data-go]") && go());
      w.addEventListener("keydown", (ev) => ev.key === "Enter" && go());
      setTimeout(() => $("[data-url]", w)?.focus(), 30);
      return modal({ title: `Test ingress rule · ${name}`, body: w });
    }
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

  async newTunnel(node) {
    const inv = S.inv.cloudflared.find((x) => x.name === node) || {};
    const accs = S.inv.cf_accounts;
    if (!accs.length) return toast("Add a Cloudflare account (with API token) in config.yaml first.", "bad");
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

  async addHost(ref, name) {
    const changed = await taskModal({
      title: `Add hostname · ${name}`, submit: "Add & apply", size: "",
      html: `<div class="two"><label>Public hostname<input name="hostname" type="text" placeholder="erp.selatwave.com" required autocomplete="off"></label>
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

// ================================================================ CONFIG
PAGES.config = {
  mount(v, params) {
    setHeader("Config", "Edit → validate → review diff → apply (auto backup & rollback)");
    const opts = [
      ...S.inv.haproxy.map((n) => ({ v: `haproxy/${n.name}`, l: `HAProxy · ${n.name} — ${n.config_path}` })),
      ...S.inv.cloudflared.flatMap((n) => n.tunnels.filter((t) => !t.remote).map((t) => ({ v: `tunnel/${n.name}:${t.name}`, l: `Tunnel · ${t.name} @ ${n.name} — ${t.config_path}` }))),
    ];
    const sel = params.length >= 2 ? `${params[0]}/${params[1]}` : opts[0]?.v;
    v.innerHTML = `<div class="panel"><div class="bd" style="display:flex;flex-direction:column;gap:12px">
        <div class="ed-bar"><select id="cfgTarget">${opts.map((o) => `<option value="${esc(o.v)}" ${o.v === sel ? "selected" : ""}>${esc(o.l)}</option>`).join("")}</select>
          <button class="btn" id="cfgReload" title="Re-read from server">Reload</button>
          <select id="cfgBackups"><option value="">Backups…</option></select>
          <span class="dirty hidden" id="cfgDirty">● unsaved changes</span><span class="grow"></span>
          <button class="btn" id="cfgValidate" title="Ctrl+S">Validate</button><button class="btn pri" id="cfgApply">Review & apply</button></div>
        <div class="muted small" id="cfgInfo"></div>
        <div class="editor"><div class="gut" id="cfgGut">1</div><textarea id="cfgText" spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off"></textarea></div>
        <pre class="out hidden" id="cfgOut"></pre></div></div>`;
    S.editor = { target: sel, original: "", hash: null, dirty: false };
    const ta = $("#cfgText"), gut = $("#cfgGut");
    const lines = () => { const n = ta.value.split("\n").length; gut.textContent = Array.from({ length: n }, (_, i) => i + 1).join("\n"); };
    const mark = () => { S.editor.dirty = ta.value !== S.editor.original; $("#cfgDirty").classList.toggle("hidden", !S.editor.dirty); };
    ta.addEventListener("input", () => { lines(); mark(); });
    ta.addEventListener("scroll", () => { gut.scrollTop = ta.scrollTop; });
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Tab") { e.preventDefault(); document.execCommand("insertText", false, "    "); }
      if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); this.validate(); }
    });
    this._lines = lines; this._mark = mark;
    $("#cfgTarget").addEventListener("change", (e) => {
      if (S.editor.dirty && !window.confirm("Discard unapplied edits?")) { e.target.value = S.editor.target; return; }
      S.editor.dirty = false; location.hash = `#/config/${e.target.value}`;
    });
    $("#cfgReload").addEventListener("click", () => { if (!S.editor.dirty || window.confirm("Discard your edits and reload from server?")) this.read(); });
    $("#cfgValidate").addEventListener("click", () => this.validate());
    $("#cfgApply").addEventListener("click", () => this.review());
    $("#cfgBackups").addEventListener("change", (e) => this.loadBackup(e.target.value));
  },
  async load(params, manual) { if (manual && S.editor && !S.editor.loaded) await this.read(); },
  url(suffix = "") { const [kind, ref] = S.editor.target.split("/"); return `/api/cfg/${kind}/${encodeURIComponent(ref)}${suffix}`; },
  out(text, ok) { const o = $("#cfgOut"); o.classList.remove("hidden", "ok", "bad"); o.classList.add(ok ? "ok" : "bad"); o.textContent = text; },
  async read() {
    if (!S.editor.target) return;
    const d = await api(this.url());
    S.editor.loaded = true; S.editor.original = d.content; S.editor.hash = d.hash;
    $("#cfgText").value = d.content; this._lines(); this._mark();
    $("#cfgInfo").innerHTML = `<span class="mono">${esc(d.path)}</span> · loaded ${new Date().toLocaleTimeString()} · sha256 ${esc(d.hash.slice(0, 12))}`;
    $("#cfgOut").classList.add("hidden");
    this.backups();
  },
  async backups() {
    try {
      const b = (await api(this.url("/backups"))).backups;
      $("#cfgBackups").innerHTML = `<option value="">Backups (${b.length})…</option>` + b.map((x) => `<option value="${esc(x.name)}">${esc(fmt.time(x.mtime))} · ${fmt.bytes(x.size)}</option>`).join("");
    } catch { /* ignore */ }
  },
  async loadBackup(name) {
    if (!name) return;
    $("#cfgBackups").value = "";
    if (S.editor.dirty && !window.confirm("Replace your current edits with this backup?")) return;
    try {
      const d = await api(this.url(`/backups/${encodeURIComponent(name)}`));
      $("#cfgText").value = d.content; this._lines(); this._mark();
      this.out(`Loaded backup ${name} into the editor.\nClick "Review & apply" to restore it (it will be validated and the current file backed up first).`, true);
    } catch (e) { toast(e.message, "bad"); }
  },
  async validate() {
    const b = $("#cfgValidate"); busy(b, true);
    try { const r = await api(this.url("/validate"), { body: { content: $("#cfgText").value } }); this.out((r.ok ? "✔ Valid\n\n" : "✘ Invalid\n\n") + r.output, r.ok); }
    catch (e) { this.out(e.message, false); } finally { busy(b, false); }
  },
  async review() {
    const content = $("#cfgText").value;
    let d;
    try { d = await api(this.url("/diff"), { body: { content } }); } catch (e) { return toast(e.message, "bad"); }
    if (!d.diff) return toast("No changes compared to the file on the server.");
    const stale = d.current_hash !== S.editor.hash;
    const isHap = S.editor.target.startsWith("haproxy/");
    const ok = await modal({
      title: `Apply changes · ${S.editor.target.split("/")[1]}`,
      body: `<div class="row"><span class="pill ok">+${d.added}</span><span class="pill crit">−${d.removed}</span><span class="muted small">
        ${isHap ? "Validate with <code>haproxy -c</code> → backup → write → <code>systemctl reload</code> (graceful)" : "Validate with <code>cloudflared ingress validate</code> → backup → write → <code>systemctl restart</code> (tunnel reconnects in a few seconds)"} → health check → auto-rollback on failure.</span></div>
        ${stale ? `<div class="out bad">The file on the server changed since you loaded it. Apply will be refused — reload and redo your edits.</div>` : ""}
        ${renderDiff(d.diff)}`,
      actions: [{ label: "Cancel", value: false }, { label: "Apply now", cls: isHap ? "pri" : "danger", value: true }],
    });
    if (!ok) return;
    const b = $("#cfgApply"); busy(b, true);
    this.out("Applying…", true);
    try {
      const r = await api(this.url("/apply"), { body: { content, base_hash: S.editor.hash } });
      const head = { applied: "✔ Applied", noop: "No changes", validate: "✘ Validation failed — nothing changed", rolled_back: "✘ Activation failed — ROLLED BACK to previous config",
        conflict: "✘ Conflict", backup: "✘ Could not write backup — nothing changed", write: "✘ Write failed" }[r.stage] || r.stage;
      this.out(`${head}${r.backup ? `\nBackup: ${r.backup}` : ""}\n\n${r.output}`, r.ok);
      if (r.ok) { toast("Config applied", "ok"); await this.read(); this.out(`${head}${r.backup ? `\nBackup: ${r.backup}` : ""}\n\n${r.output}`, true); }
      else toast(head, "bad");
    } catch (e) { this.out(e.message, false); } finally { busy(b, false); }
  },
};

// ================================================================ ACTIVITY
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

boot();
