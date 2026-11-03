/* Gateway Console web UI — HAProxy "+ Add" / Edit form (side panel).
 * One form for frontends and backends: Frontend (New / Use existing / None), Backend (New / Use
 * existing / None) and an optional Cloudflare step (tunnel hostname + DNS). Editing opens the same
 * form with only that part. The right column shows, live, what will happen, checks and the exact
 * haproxy.cfg diff; "Review & apply" runs haproxy -c and applies through the safe-apply path. */
"use strict";

const HPF = {
  F: null,
  BAL: [["roundrobin", "roundrobin — take turns"], ["leastconn", "leastconn — fewest connections"], ["source", "source — same client, same server"],
    ["first", "first — fill one server, then the next"], ["static-rr", "static-rr — fixed weights"], ["uri", "uri — same URL, same server"], ["random", "random"]],
  COND: [["host", "Host is"], ["path_beg", "Path starts with"], ["path_end", "Path ends with"], ["path", "Path is"], ["path_reg", "Path matches (regex)"],
    ["header", "Header"], ["src", "Source IP is"], ["method", "Method is"], ["sni", "TLS SNI is (TCP)"]],
  ACT: [["backend", "Send to backend"], ["redirect", "Redirect to URL"], ["redirect_https", "Redirect to HTTPS"], ["deny", "Deny (403)"],
    ["allow_only", "Allow only from IPs"], ["set_header", "Set request header"]],

  // ---------------------------------------------------------------- state helpers
  get(path) { return path.split(".").reduce((o, k) => (o == null ? o : o[k]), this.F); },
  set(path, v) {
    const ks = path.split("."), last = ks.pop();
    const o = ks.reduce((o, k) => o[k], this.F);
    o[last] = v;
  },
  clone: (x) => JSON.parse(JSON.stringify(x)),
  emptyServer: () => ({ name: "", addr: "", weight: "", maxconn: "", check: true, backup: false, disabled: false, ssl: false, verify_none: true,
    sni: "", send_proxy: "", inter: "", rise: "", fall: "", cookie: "", extra: "" }),
  emptyBackend(mode) {
    return { kind: "backend", name: "", mode, balance: "roundrobin", sticky: { type: "none", cookie: "SERVERID" },
      health: { type: "connect", method: "GET", path: "/", host: "", expect: "" }, check: { inter: "", rise: "", fall: "" },
      forwardfor: mode === "http", headers: [], timeouts: { connect: "", server: "", check: "", tunnel: "" }, retries: "", redispatch: false,
      servers: [this.emptyServer()], advanced: "" };
  },
  emptyFrontend(mode) {
    return { kind: "frontend", name: "", mode, binds: [{ addr: mode === "tcp" ? "*:" : "*:80", ssl: false, crt: "", h2: false, extra: "" }], log: true,
      forwardfor: false, maxconn: "", timeouts: { client: "", "http-request": "" }, ratelimit: "", force_https: false, headers: [], rules: [],
      default_backend: "", advanced: "" };
  },
  effMode(m) { return (m && m.mode) || this.F.data.defaults_mode; },
  port(m) { const a = (m?.binds?.[0]?.addr || ""); const p = a.split(":").pop(); return /^\d+$/.test(p) ? p : ""; },
  beName() {
    const b = this.F.be;
    return b.choice === "new" || b.choice === "edit" ? b.model.name : b.choice === "existing" ? b.existing : "";
  },

  // ---------------------------------------------------------------- open / close
  async open(node, opts = {}) {
    if (this.F) this.close(true);
    const data = await api(`/api/haproxy/${encodeURIComponent(node)}/model`);
    const F = this.F = { node, opts, data, mode: opts.mode || "add", type: "http", seq: 0,
      fe: { choice: "none", existing: "", model: null, tab: "routing" }, be: { choice: "none", existing: "", model: null, tab: "servers" },
      cf: { on: false, sel: "", hostname: "", service: "", dns: true, touched: false }, auto: { beName: true, feName: true }, probe: {}, open: {} };
    if (F.mode === "edit") {
      const src = (opts.kind === "frontend" ? data.frontends : data.backends).find((x) => x.name === opts.name);
      if (!src) throw new Error(`${opts.kind} ${opts.name} not found in haproxy.cfg`);
      const part = opts.kind === "frontend" ? F.fe : F.be;
      part.choice = "edit"; part.model = this.clone(src); part.tab = opts.tab || part.tab;
      if (opts.addServer) { part.model.servers.push(this.emptyServer()); part.tab = "servers"; }
      F.type = this.effMode(part.model) === "tcp" ? "tcp" : "http";
    } else this.setType("http");
    this.build();
  },
  setType(t) {
    const F = this.F;
    F.type = t;
    const fes = F.data.frontends.filter((f) => this.effMode(f) === t);
    F.be = { choice: "new", existing: "", model: this.emptyBackend(t), tab: "servers" };
    if (t === "http" && fes.length) {
      F.fe = { choice: "existing", existing: fes[0].name, model: null, tab: "routing" };
      this.loadExistingFe();
    } else {
      const m = this.emptyFrontend(t);
      m.default_backend = t === "tcp" ? "@be" : "";
      if (t === "http") m.rules.push(this.autoRule());
      F.fe = { choice: "new", existing: "", model: m, tab: t === "tcp" ? "bind" : "routing" };
    }
    F.auto = { beName: true, feName: true };
    F.cf = { on: false, sel: "", hostname: "", service: "", dns: true, touched: false };
  },
  autoRule() { return { cond: "host", value: "", hname: "", action: "backend", target: "@be", _auto: true }; },
  loadExistingFe() {
    const F = this.F, src = F.data.frontends.find((f) => f.name === F.fe.existing);
    F.fe.model = this.clone(src);
    if (F.mode === "add" && F.type === "http") F.fe.model.rules.push(this.autoRule());
  },
  close(force) {
    if (!this.F) return;
    this.el?.remove(); this.bg?.remove();
    document.removeEventListener("keydown", this._key);
    this.F = null;
    if (!force) schedule();
  },

  // ---------------------------------------------------------------- building the panel
  build() {
    const F = this.F;
    const bg = document.createElement("div"); bg.className = "drawer-bg";
    const d = document.createElement("aside"); d.className = "drawer hpf";
    const title = F.mode === "edit" ? `Edit ${F.opts.kind} ${esc(F.opts.name)}` : "Add";
    const usedBy = F.mode === "edit" && F.opts.kind === "backend" ? (F.be.model.used_by || []) : [];
    d.innerHTML = `<div class="dhd"><div class="grow" style="min-width:0"><div class="tag">HAProxy · ${esc(F.node)}</div><h3>${title}
        ${usedBy.length ? `<span class="tag" style="margin-left:8px">used by ${esc(usedBy.join(", "))}</span>` : ""}</h3></div>
        ${F.mode === "add" ? `<div class="seg2" data-type><button class="${F.type === "http" ? "on" : ""}" data-v="http">Website (HTTP)</button><button class="${F.type === "tcp" ? "on" : ""}" data-v="tcp">TCP service</button></div>` : ""}
        <button class="btn ghost sm" data-close title="Close (Esc)">✕</button></div>
      <div class="hpf-cols"><div class="hpf-left" data-left></div><div class="hpf-right" data-right><div class="muted small">Working out the changes…</div></div></div>
      <div class="hpf-foot">${F.mode === "edit" ? `<button class="btn danger" data-del>Delete…</button>` : ""}<span class="grow"></span>
        <button class="btn" data-close>Cancel</button><button class="btn pri" data-review>Review diff &amp; apply</button></div>`;
    document.body.append(bg, d);
    this.el = d; this.bg = bg;
    requestAnimationFrame(() => { bg.classList.add("open"); d.classList.add("open"); });
    clearTimeout(S.timer);
    this._key = (e) => { if (e.key === "Escape" && !$(".modal-bg")) this.close(); };
    document.addEventListener("keydown", this._key);
    d.addEventListener("click", (e) => this.onClick(e));
    d.addEventListener("input", (e) => this.onInput(e));
    d.addEventListener("change", (e) => this.onInput(e, true));
    this.render();
  },
  render() {
    const F = this.F;
    const parts = [];
    let n = 0;
    if (F.mode === "add" || F.opts.kind === "frontend") parts.push(this.partFe(++n));
    if (F.mode === "add" || F.opts.kind === "backend") parts.push(this.partBe(++n));
    if (F.mode === "add" && F.fe.choice !== "none") parts.push(this.partCf(++n));
    const left = $("[data-left]", this.el);
    const keep = document.activeElement?.dataset?.b;
    left.innerHTML = parts.join("");
    if (keep) { const el = $(`[data-b="${CSS.escape(keep)}"]`, left); if (el) { el.focus(); if (el.setSelectionRange && el.type === "text") el.setSelectionRange(el.value.length, el.value.length); } }
    $$("[data-type] button", this.el).forEach((b) => b.classList.toggle("on", b.dataset.v === F.type));
    this.preview();
  },

  // ---------------------------------------------------------------- field builders
  inp(label, path, ph = "", cls = "") {
    return `<label class="f ${cls}">${label}<input type="text" data-b="${path}" value="${esc(this.get(path) ?? "")}" placeholder="${esc(ph)}" spellcheck="false"></label>`;
  },
  sel(label, path, options, rr = false, cls = "") {
    const v = this.get(path) ?? "";
    return `<label class="f ${cls}">${label}<select data-b="${path}" ${rr ? "data-rr" : ""}>${options.map(([k, l]) => `<option value="${esc(k)}" ${String(k) === String(v) ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></label>`;
  },
  chk(label, path, rr = false) {
    return `<label class="ck"><input type="checkbox" data-b="${path}" ${this.get(path) ? "checked" : ""} ${rr ? "data-rr" : ""}> ${label}</label>`;
  },
  seg(path, opts) {
    const v = this.get(path);
    return `<span class="seg2" data-seg="${path}">${opts.map(([k, l]) => `<button type="button" class="${k === v ? "on" : ""}" data-v="${k}">${l}</button>`).join("")}</span>`;
  },
  tabs(path, list) {
    const v = this.get(path);
    return `<div class="ptabs" data-tabs="${path}">${list.map(([k, l, c]) => `<button type="button" class="${k === v ? "on" : ""}" data-v="${k}">${l}${c ? ` <em>${c}</em>` : ""}</button>`).join("")}</div>`;
  },
  backendOpts(extra = []) {
    const F = this.F, mode = F.type, out = [...extra];
    if (F.be.choice === "new" && F.mode === "add") out.push(["@be", `${F.be.model.name || "the new backend"} (new ↓)`]);
    F.data.backends.forEach((b) => out.push([b.name, `${b.name}${this.effMode(b) !== mode ? ` (${this.effMode(b)})` : ""}`]));
    return out;
  },

  // ---------------------------------------------------------------- frontend part
  partFe(n) {
    const F = this.F, fe = F.fe, add = F.mode === "add";
    const head = `<div class="ph"><span class="n">${n}</span><b>Frontend</b><span class="sub">where traffic comes in</span>
      ${add ? this.seg("fe.choice", [["new", "New"], ["existing", "Use existing"], ["none", "None"]]) : ""}</div>`;
    if (fe.choice === "none") return `<div class="part">${head}<div class="pb muted small">No frontend change — just the backend.</div></div>`;
    const m = fe.model;
    const fes = F.data.frontends.filter((f) => this.effMode(f) === F.type);
    let top = "";
    if (fe.choice === "existing") {
      top = fes.length ? this.sel("Frontend", "fe.existing", fes.map((f) => [f.name, `${f.name} — ${f.summary}`]), true)
        : `<div class="muted small">No ${F.type} frontend yet — choose New.</div>`;
    } else {
      top = `<div class="g3">${this.inp("Name", "fe.model.name", "fe_web")}${this.sel("Mode", "fe.model.mode", [["http", "http (websites)"], ["tcp", "tcp (anything else)"], ["", `inherit (${F.data.defaults_mode})`]], true)}
        ${this.inp("Listen on (address:port)", "fe.model.binds.0.addr", "*:80")}</div>`;
    }
    if (!m) return `<div class="part">${head}<div class="pb">${top}</div></div>`;
    const tcp = this.effMode(m) === "tcp";
    const tabs = this.tabs("fe.tab", [["routing", "Routing", m.rules.length || ""], ["bind", "Bind & HTTPS", m.binds.length], ["headers", "Headers & redirects", m.headers.length || ""],
      ["limits", "Limits & timeouts"], ["advanced", "Advanced", m.advanced ? m.advanced.split("\n").length : ""]]);
    return `<div class="part">${head}<div class="pb">${top}${tabs}${this["fe_" + fe.tab](m, tcp)}</div></div>`;
  },
  fe_routing(m, tcp) {
    const conds = this.COND.filter(([k]) => (tcp ? ["sni", "src"] : this.COND.map((c) => c[0]).filter((c) => c !== "sni")).includes(k));
    const acts = tcp ? this.ACT.filter(([k]) => ["backend", "deny"].includes(k)) : this.ACT;
    const rows = m.rules.map((r, i) => {
      const p = `fe.model.rules.${i}`;
      let tgt;
      if (r.action === "backend") tgt = this.sel("", `${p}.target`, this.backendOpts([["", "— choose —"]]), true, "nolab");
      else if (r.action === "redirect_https" || r.action === "deny") tgt = `<span class="muted small">—</span>`;
      else tgt = this.inp("", `${p}.target`, { redirect: "https://new.example.com/", allow_only: "192.168.10.0/24", set_header: "X-Name: value" }[r.action], "nolab");
      return `<tr class="${r._auto ? "newrow" : ""}"><td>${this.sel("", `${p}.cond`, conds, true, "nolab")}</td>
        <td>${r.cond === "header" ? `<div class="g2">${this.inp("", `${p}.hname`, "X-Header", "nolab")}${this.inp("", `${p}.value`, "value", "nolab")}</div>` : this.inp("", `${p}.value`, { host: "app.example.com", src: "10.0.0.0/8", method: "GET", sni: "app.example.com" }[r.cond] || "/path", "nolab")}</td>
        <td>${this.sel("", `${p}.action`, acts, true, "nolab")}</td><td>${tgt}</td>
        <td class="rowbtns"><button type="button" class="ib" data-mv="${i}" data-d="-1" title="Move up">↑</button><button type="button" class="ib" data-mv="${i}" data-d="1" title="Move down">↓</button>
          <button type="button" class="ib rm" data-rmrule="${i}" title="Remove">✕</button></td></tr>`;
    }).join("");
    return `<table class="ft"><tr><th style="width:24%">When</th><th>Value</th><th style="width:20%">Then</th><th style="width:22%">Target</th><th style="width:78px"></th></tr>${rows ||
      `<tr><td colspan="5" class="muted small">No rules — everything goes to the default backend.</td></tr>`}</table>
      <div class="row"><button type="button" class="lnk" data-addrule>+ Add rule</button><span class="muted small">Rules are checked top to bottom; the first match wins.</span></div>
      ${this.sel("Everything else goes to (default backend)", "fe.model.default_backend", this.backendOpts([["", "— none —"]]), true)}`;
  },
  fe_bind(m, tcp) {
    const rows = m.binds.map((b, i) => `<div class="bindrow">${this.inp(i ? "" : "Address : port", `fe.model.binds.${i}.addr`, "*:443", "nolab grow")}
        ${tcp ? "" : `${this.chk("HTTPS", `fe.model.binds.${i}.ssl`, true)}${b.ssl ? `${this.inp("", `fe.model.binds.${i}.crt`, "/etc/haproxy/certs/site.pem", "nolab grow")}${this.chk("HTTP/2", `fe.model.binds.${i}.h2`)}` : ""}`}
        ${m.binds.length > 1 ? `<button type="button" class="ib rm" data-rmbind="${i}">✕</button>` : ""}</div>`).join("");
    return `${rows}<div class="row"><button type="button" class="lnk" data-addbind>+ Add address</button></div>
      <details class="more" ${m.binds.some((b) => b.ssl) ? "open" : ""}><summary>About HTTPS</summary><div class="muted small">Leave HTTPS off when traffic arrives through Cloudflare Tunnel — Cloudflare already handles the certificate and cloudflared talks to HAProxy over your LAN.
        Turn it on only for clients that reach HAProxy directly; you'll need a .pem certificate (or a folder of them) on the HAProxy node.</div></details>
      ${m.binds.some((b) => b.extra) ? `<div class="muted small">Extra bind options kept: ${m.binds.filter((b) => b.extra).map((b) => `<code>${esc(b.extra)}</code>`).join(" ")}</div>` : ""}`;
  },
  hdrRows(base, list) {
    return `${list.map((h, i) => `<div class="hdrrow">${this.sel("", `${base}.${i}.dir`, [["request", "Request header"], ["response", "Response header"]], false, "nolab")}
      ${this.inp("", `${base}.${i}.name`, "X-Header", "nolab")}${this.inp("", `${base}.${i}.value`, "value", "nolab grow")}<button type="button" class="ib rm" data-rmhdr="${base}" data-i="${i}">✕</button></div>`).join("")}
      <div class="row"><button type="button" class="lnk" data-addhdr="${base}">+ Add header</button></div>`;
  },
  fe_headers(m, tcp) {
    if (tcp) return `<div class="muted small">Headers and redirects are for HTTP mode.</div>`;
    return `${this.chk("Redirect every plain-HTTP request to HTTPS (only if this frontend also listens with HTTPS)", "fe.model.force_https")}
      ${this.chk("Pass the visitor's IP to the app (X-Forwarded-For)", "fe.model.forwardfor")}
      <div class="sec2">Set headers on every request / response</div>${this.hdrRows("fe.model.headers", m.headers)}`;
  },
  fe_limits(m, tcp) {
    return `<div class="g3">${this.inp("Max connections", "fe.model.maxconn", "e.g. 2000")}${this.inp("Client timeout", "fe.model.timeouts.client", "e.g. 30s")}
      ${tcp ? "" : this.inp("Request header timeout", "fe.model.timeouts.http-request", "e.g. 10s")}</div>
      ${tcp ? "" : `<div class="g3">${this.inp("Rate limit per IP (requests / 10 s)", "fe.model.ratelimit", "off")}</div><div class="muted small">Over the limit, a visitor gets "429 Too Many Requests" until they slow down.</div>`}
      ${this.chk(tcp ? "Log connections (option tcplog)" : "Log requests (option httplog)", "fe.model.log")}
      <div class="muted small">Empty fields use the defaults section.</div>`;
  },
  fe_advanced(m) { return this.advanced("fe.model.advanced", m); },
  advanced(path, m) {
    return `<div class="muted small">Any other HAProxy directives for this section, one per line. Lines the form doesn't understand are kept here exactly as written — nothing is lost.</div>
      <textarea class="adv" rows="7" data-b="${path}" spellcheck="false" placeholder="e.g. http-request return status 200 content-type text/plain string ok if { path /ping }">${esc(this.get(path) || "")}</textarea>`;
  },

  // ---------------------------------------------------------------- backend part
  partBe(n) {
    const F = this.F, be = F.be, add = F.mode === "add";
    const head = `<div class="ph"><span class="n">${n}</span><b>Backend</b><span class="sub">the servers behind it</span>
      ${add ? this.seg("be.choice", [["new", "New"], ["existing", "Use existing"], ["none", "None"]]) : ""}</div>`;
    if (be.choice === "none") return `<div class="part">${head}<div class="pb muted small">No backend — the frontend only.</div></div>`;
    if (be.choice === "existing") {
      const list = F.data.backends.filter((b) => this.effMode(b) === F.type);
      return `<div class="part">${head}<div class="pb">${list.length ? this.sel("Backend", "be.existing", [["", "— choose —"], ...list.map((b) => [b.name, `${b.name} — ${b.summary}`])], true)
        : `<div class="muted small">No ${F.type} backend yet — choose New.</div>`}
        <div class="muted small">To change its servers, use Edit on that backend in the list.</div></div></div>`;
    }
    const m = be.model;
    const top = `<div class="g4">${this.inp("Name", "be.model.name", "be_app")}${this.sel("Load balancing", "be.model.balance", [["", "— default —"], ...this.BAL])}
      ${this.sel("Sticky sessions", "be.model.sticky.type", F.type === "tcp" || this.effMode(m) === "tcp" ? [["none", "Off"]] : [["none", "Off"], ["cookie", "Cookie"]], true)}
      ${this.sel("Mode", "be.model.mode", [["http", "http"], ["tcp", "tcp"], ["", `inherit (${F.data.defaults_mode})`]], true)}</div>`;
    const tabs = this.tabs("be.tab", [["servers", "Servers", m.servers.length], ["health", "Health check"], ["headers", "Headers", m.headers.length || ""],
      ["timeouts", "Timeouts & retries"], ["advanced", "Advanced", m.advanced ? m.advanced.split("\n").length : ""]]);
    return `<div class="part">${head}<div class="pb">${top}${tabs}${this["be_" + be.tab](m)}</div></div>`;
  },
  be_servers(m) {
    const F = this.F;
    const rows = m.servers.map((s, i) => {
      const p = `be.model.servers.${i}`, pr = F.probe[s.addr];
      const st = pr === undefined ? "" : pr ? `<span class="ok" title="reachable from ${esc(F.node)}">●</span>` : `<span class="bad" title="not reachable from ${esc(F.node)}">●</span>`;
      const open = F.open[i];
      return `<tr><td>${this.inp("", `${p}.name`, "web1", "nolab")}</td><td><div class="addr">${this.inp("", `${p}.addr`, "10.0.20.11:80", "nolab")}${st}</div></td>
        <td>${this.inp("", `${p}.weight`, "100", "nolab")}</td><td>${this.inp("", `${p}.maxconn`, "—", "nolab")}</td>
        <td>${this.chk("check", `${p}.check`)}</td><td>${this.chk("backup (DR)", `${p}.backup`)}</td>
        <td class="rowbtns"><button type="button" class="ib ${open ? "on" : ""}" data-more="${i}" title="More options">⋯</button><button type="button" class="ib rm" data-rmsrv="${i}" title="Remove">✕</button></td></tr>
        ${open ? `<tr class="srvmore"><td colspan="7"><div class="g4">${this.chk("HTTPS to this server", `${p}.ssl`, true)}${s.ssl ? this.chk("don't verify its certificate", `${p}.verify_none`) : ""}
          ${s.ssl ? this.inp("SNI", `${p}.sni`, "app.example.com") : ""}${this.sel("PROXY protocol", `${p}.send_proxy`, [["", "Off"], ["v1", "send-proxy (v1)"], ["v2", "send-proxy-v2"]])}</div>
          <div class="g4">${this.inp("Check every", `${p}.inter`, "2s")}${this.inp("Up after (checks)", `${p}.rise`, "2")}${this.inp("Down after (checks)", `${p}.fall`, "3")}${this.inp("Cookie value", `${p}.cookie`, s.name || "")}</div>
          <div class="g2">${this.chk("Start disabled (no traffic)", `${p}.disabled`)}${this.inp("Other options (kept as written)", `${p}.extra`, "e.g. resolvers dns init-addr none")}</div></td></tr>` : ""}`;
    }).join("");
    return `<table class="ft"><tr><th style="width:18%">Name</th><th>Address : port</th><th style="width:70px">Weight</th><th style="width:80px">Max conn</th><th></th><th></th><th style="width:58px"></th></tr>${rows}</table>
      <div class="row"><button type="button" class="lnk" data-addsrv>+ Add server</button><button type="button" class="lnk" data-probe>Test servers from ${esc(this.F.node)}</button>
        <span class="muted small" data-probemsg></span></div>
      <div class="muted small">Backup servers only get traffic when every normal server is down — use them for DR.</div>`;
  },
  be_health(m) {
    const http = this.effMode(m) !== "tcp";
    return `<div class="g3">${this.sel("Type", "be.model.health.type", http ? [["connect", "Connect (TCP)"], ["http", "HTTP request"]] : [["connect", "Connect (TCP)"]], true)}</div>
      ${m.health.type === "http" ? `<div class="g4">${this.sel("Method", "be.model.health.method", [["GET", "GET"], ["HEAD", "HEAD"], ["OPTIONS", "OPTIONS"]])}${this.inp("Path", "be.model.health.path", "/")}
        ${this.inp("Host header", "be.model.health.host", "optional")}${this.inp("Healthy status", "be.model.health.expect", "200-399")}</div>` : `<div class="muted small">A server is healthy when HAProxy can open a connection to it.</div>`}
      <div class="sec2">For every server (each can override under ⋯)</div>
      <div class="g3">${this.inp("Check every", "be.model.check.inter", "2s")}${this.inp("Up after (checks)", "be.model.check.rise", "2")}${this.inp("Down after (checks)", "be.model.check.fall", "3")}</div>
      <div class="muted small">Only servers with "check" ticked are health-checked.</div>`;
  },
  be_headers(m) {
    if (this.effMode(m) === "tcp") return `<div class="muted small">Headers are for HTTP mode.</div>`;
    return `${this.chk("Pass the visitor's IP to the app (X-Forwarded-For)", "be.model.forwardfor")}
      ${m.sticky.type === "cookie" ? this.inp("Sticky cookie name", "be.model.sticky.cookie", "SERVERID") : ""}
      <div class="sec2">Set headers</div>${this.hdrRows("be.model.headers", m.headers)}`;
  },
  be_timeouts(m) {
    return `<div class="g4">${this.inp("Connect", "be.model.timeouts.connect", "5s")}${this.inp("Server", "be.model.timeouts.server", "30s")}${this.inp("Health check", "be.model.timeouts.check", "")}
      ${this.inp("Tunnel (WebSocket)", "be.model.timeouts.tunnel", "1h")}</div>
      <div class="g3">${this.inp("Retries", "be.model.retries", "3")}</div>${this.chk("If a server fails, retry the request on another one (option redispatch)", "be.model.redispatch")}
      <div class="muted small">Empty fields use the defaults section.</div>`;
  },
  be_advanced(m) { return this.advanced("be.model.advanced", m); },

  // ---------------------------------------------------------------- cloudflare part
  partCf(n) {
    const F = this.F, cf = F.cf, tl = F.data.tunnels || [];
    const head = `<div class="ph"><span class="n">${n}</span><b>Cloudflare</b><span class="sub">optional — publish through a tunnel</span>
      ${tl.length ? `<span class="seg2" data-cfon><button type="button" class="${cf.on ? "on" : ""}" data-v="1">Publish</button><button type="button" class="${cf.on ? "" : "on"}" data-v="0">Skip</button></span>` : ""}</div>`;
    if (!tl.length) return `<div class="part">${head}<div class="pb muted small">No cloudflared node added yet (Settings → Nodes).</div></div>`;
    if (!cf.on) return `<div class="part">${head}</div>`;
    return `<div class="part">${head}<div class="pb"><div class="g3">${this.sel("Tunnel", "cf.sel", [["", "— choose —"], ...tl.map((t) => [`${t.node}:${t.tunnel}`, `${t.tunnel} — ${t.node}${t.remote ? " (token-run: edit in Zero Trust)" : ""}`])], true)}
      ${this.inp(F.type === "tcp" ? "Public hostname" : "Public hostname", "cf.hostname", F.type === "tcp" ? "mc.example.com" : "app.example.com")}
      ${this.inp("cloudflared sends it to", "cf.service", "http://10.0.10.21:80")}</div>${this.chk("Create the DNS record (CNAME to the tunnel)", "cf.dns")}
      <div class="muted small">The hostname is added to the tunnel's ingress (tunnel restarts) and the DNS record created. If anything fails, the HAProxy change is undone too.</div></div></div>`;
  },

  // ---------------------------------------------------------------- events
  onInput(e, change) {
    const el = e.target.closest("[data-b]");
    if (!el) return;
    if (e.type === "input" && (el.tagName === "SELECT" || el.type === "checkbox")) return;
    if (e.type === "change" && el.tagName !== "SELECT" && el.type !== "checkbox") return;
    const path = el.dataset.b;
    const v = el.type === "checkbox" ? el.checked : el.value;
    this.set(path, v);
    this.sync(path);
    if (el.hasAttribute("data-rr")) this.render();
    else { this.refreshAuto(); this.preview(); }
  },
  refreshAuto() {
    // fields filled in automatically (names, Cloudflare hostname/service) follow what you type elsewhere
    ["be.model.name", "fe.model.name", "cf.hostname", "cf.service"].forEach((p) => {
      const el = $(`[data-b="${p}"]`, this.el);
      if (el && el !== document.activeElement) el.value = this.get(p) ?? "";
    });
    $$("[data-b$='.target'] option[value='@be']", this.el).forEach((o) => { o.textContent = `${this.F.be.model?.name || "the new backend"} (new ↓)`; });
  },
  sync(path) {
    const F = this.F;
    if (F.mode !== "add") return;
    const rule = F.fe.model?.rules?.find((r) => r._auto);
    if (path === "be.model.name") F.auto.beName = false;
    if (path === "fe.model.name") F.auto.feName = false;
    if (path === "cf.hostname" || path === "cf.service") F.cf.touched = true;
    if (path === "fe.existing") this.loadExistingFe();
    // hostname typed in the routing rule → names, Cloudflare hostname
    const host = rule && rule.cond === "host" ? rule.value.split(/\s+/)[0] : "";
    const base = (host.split(".")[0] || "").toLowerCase().replace(/[^a-z0-9]+/g, "_");
    if (F.be.choice === "new" && F.auto.beName && base) F.be.model.name = "be_" + base;
    if (F.type === "tcp" && F.fe.choice === "new" && F.auto.feName && F.be.model?.name) F.fe.model.name = F.be.model.name.replace(/^be_/, "fe_");
    if (!F.cf.touched) {
      if (host) F.cf.hostname = host;
      const fm = F.fe.model, port = this.port(fm);
      if (port) F.cf.service = `${F.type === "tcp" ? "tcp" : "http"}://${F.data.host}:${port}`;
    }
    if (path === "cf.sel" && F.cf.sel) { const t = F.data.tunnels.find((x) => `${x.node}:${x.tunnel}` === F.cf.sel); if (t?.remote) toast(`${t.tunnel} is token-run: add its hostname in the Zero Trust dashboard`, "bad"); }
  },
  async onClick(e) {
    const F = this.F, b = e.target.closest("button,[data-v]");
    if (!b || !F) return;
    if (b.matches("[data-close]")) return this.close();
    const seg = b.closest("[data-seg],[data-tabs],[data-type],[data-cfon]");
    if (seg && b.dataset.v !== undefined) {
      if (seg.dataset.type !== undefined) { if (b.dataset.v !== F.type) { this.setType(b.dataset.v); } }
      else if (seg.dataset.cfon !== undefined) { F.cf.on = b.dataset.v === "1"; this.sync(""); }
      else {
        const path = seg.dataset.seg || seg.dataset.tabs;
        this.set(path, b.dataset.v);
        if (path === "fe.choice") this.feChoice(b.dataset.v);
        if (path === "be.choice") this.beChoice(b.dataset.v);
      }
      return this.render();
    }
    const m = (part) => F[part].model;
    if (b.matches("[data-addrule]")) m("fe").rules.push({ cond: F.type === "tcp" ? "sni" : "host", value: "", hname: "", action: "backend", target: "" });
    else if (b.dataset.rmrule !== undefined) m("fe").rules.splice(+b.dataset.rmrule, 1);
    else if (b.dataset.mv !== undefined) {
      const r = m("fe").rules, i = +b.dataset.mv, j = i + +b.dataset.d;
      if (j < 0 || j >= r.length) return;
      [r[i], r[j]] = [r[j], r[i]];
    } else if (b.matches("[data-addbind]")) m("fe").binds.push({ addr: "", ssl: false, crt: "", h2: false, extra: "" });
    else if (b.dataset.rmbind !== undefined) m("fe").binds.splice(+b.dataset.rmbind, 1);
    else if (b.dataset.addhdr) this.get(b.dataset.addhdr).push({ dir: "request", name: "", value: "" });
    else if (b.dataset.rmhdr) this.get(b.dataset.rmhdr).splice(+b.dataset.i, 1);
    else if (b.matches("[data-addsrv]")) { m("be").servers.push(this.emptyServer()); }
    else if (b.dataset.rmsrv !== undefined) { m("be").servers.splice(+b.dataset.rmsrv, 1); F.open = {}; }
    else if (b.dataset.more !== undefined) F.open[+b.dataset.more] = !F.open[+b.dataset.more];
    else if (b.matches("[data-probe]")) return this.probe(b);
    else if (b.matches("[data-review]")) return this.review(b);
    else if (b.matches("[data-del]")) return this.remove();
    else return;
    this.render();
  },
  feChoice(v) {
    const F = this.F;
    if (v === "new") {
      const mm = this.emptyFrontend(F.type);
      if (F.type === "tcp") mm.default_backend = "@be"; else mm.rules.push(this.autoRule());
      F.fe.model = mm; F.fe.tab = F.type === "tcp" ? "bind" : "routing"; F.auto.feName = true;
    } else if (v === "existing") {
      const fes = F.data.frontends.filter((f) => this.effMode(f) === F.type);
      F.fe.existing = fes[0]?.name || "";
      if (F.fe.existing) this.loadExistingFe(); else F.fe.model = null;
      F.fe.tab = "routing";
    } else { F.fe.model = null; F.cf.on = false; }
  },
  beChoice(v) {
    const F = this.F;
    if (v === "new") { F.be.model = this.emptyBackend(F.type); F.auto.beName = true; }
    else { F.be.model = null; }
    const rule = F.fe.model?.rules?.find((r) => r._auto);
    if (rule) rule.target = v === "new" ? "@be" : v === "existing" ? (F.be.existing || "") : rule.target;
    if (F.fe.model && F.fe.model.default_backend === "@be" && v !== "new") F.fe.model.default_backend = v === "existing" ? F.be.existing : "";
  },

  // ---------------------------------------------------------------- ops, preview, review, apply
  ops() {
    const F = this.F, ops = [];
    const bn = this.beName();
    const fix = (x) => (x === "@be" ? bn : x);
    if (F.be.choice === "existing" && F.fe.model) {
      F.fe.model.rules.forEach((r) => { if (r._auto) r.target = F.be.existing; });
    }
    if (F.be.choice === "new" || F.be.choice === "edit") {
      const m = this.clone(F.be.model);
      m.servers = m.servers.filter((s) => s.name || s.addr);
      ops.push({ op: "upsert", kind: "backend", orig_name: F.be.choice === "edit" ? F.opts.name : "", model: m });
    }
    if (F.fe.model && F.fe.choice !== "none") {
      const m = this.clone(F.fe.model);
      m.rules = m.rules.filter((r) => !(r._auto && !String(r.value).trim())).map((r) => ({ ...r, target: fix(r.target) }));
      m.default_backend = fix(m.default_backend);
      m.binds = m.binds.filter((x) => x.addr && !/:$/.test(x.addr));
      ops.push({ op: "upsert", kind: "frontend", orig_name: F.fe.choice === "new" ? "" : (F.fe.choice === "edit" ? F.opts.name : F.fe.existing), model: m });
    }
    return ops;
  },
  cfBody() {
    const cf = this.F.cf;
    if (!cf.on || !cf.sel) return null;
    const [node, tunnel] = cf.sel.split(":");
    return { node, tunnel, hostname: cf.hostname, service: cf.service, dns: cf.dns };
  },
  preview() {
    clearTimeout(this._pt);
    this._pt = setTimeout(() => this.runPreview(), 450);
  },
  async runPreview(validate = false) {
    const F = this.F;
    if (!F) return null;
    const seq = ++F.seq;
    const box = $("[data-right]", this.el);
    let ops;
    try { ops = this.ops(); } catch (err) { box.innerHTML = `<div class="ferr">${esc(err.message)}</div>`; return null; }
    if (!ops.length) { box.innerHTML = `<div class="muted small">Nothing to change yet.</div>`; return null; }
    try {
      const r = await api(`/api/haproxy/${encodeURIComponent(F.node)}/plan`, { body: { ops, cloudflare: this.cfBody(), validate } });
      if (!this.F || seq !== F.seq) return null;
      F.last = { ...r, ops };
      const probe = Object.entries(F.probe).map(([a, ok]) => ({ ok, warn: !ok, text: ok ? `${a} reachable from ${F.node}` : `${a} not reachable from ${F.node} right now` }));
      const checks = [...(r.checks || []), ...probe];
      box.innerHTML = r.error ? `<div class="rh">Fix this first</div><div class="ferr">${esc(r.error)}</div>` : `
        <div class="rh">What will happen</div><ul class="plan">${(r.plan || []).map((p) => `<li>${esc(p)}</li>`).join("") || "<li class='muted'>No changes.</li>"}</ul>
        ${r.errors?.length ? `<div class="rh">Fix this first</div><ul class="chk">${r.errors.map((x) => `<li class="bad">✘ ${esc(x)}</li>`).join("")}</ul>` : ""}
        ${checks.length ? `<div class="rh">Checks</div><ul class="chk">${checks.map((c) => `<li class="${c.ok ? "ok" : c.warn ? "warn" : "bad"}">${c.ok ? "✔" : "!"} ${esc(c.text)}</li>`).join("")}</ul>` : ""}
        <div class="rh">haproxy.cfg changes <span class="muted">+${r.added || 0} −${r.removed || 0}</span></div>${renderDiff(r.diff)}`;
      return r;
    } catch (err) {
      if (this.F && seq === F.seq) box.innerHTML = `<div class="ferr">${esc(err.message)}</div>`;
      return null;
    }
  },
  async probe(btn) {
    const F = this.F, m = F.be.model;
    const servers = (m?.servers || []).map((s) => s.addr).filter(Boolean);
    const port = F.fe.choice === "new" ? this.port(F.fe.model) : "";
    busy(btn, true);
    try {
      const r = await api(`/api/haproxy/${encodeURIComponent(F.node)}/probe`, { body: { servers, port } });
      F.probe = r.servers || {};
      this.render();
      const msg = $("[data-probemsg]", this.el);
      if (msg && r.port_in_use !== null && port) msg.textContent = r.port_in_use ? `port ${port} is already in use on ${F.node}` : `port ${port} is free on ${F.node}`;
    } catch (err) { toast(err.message, "bad"); } finally { busy(btn, false); }
  },
  async review(btn) {
    const F = this.F;
    busy(btn, true);
    let r;
    try {
      if ((F.be.model?.servers || []).some((s) => s.addr) && !Object.keys(F.probe).length) {
        try { const p = await api(`/api/haproxy/${encodeURIComponent(F.node)}/probe`, { body: { servers: F.be.model.servers.map((s) => s.addr).filter(Boolean) } }); F.probe = p.servers || {}; } catch { /* optional */ }
      }
      r = await this.runPreview(true);
    } finally { busy(btn, false); }
    if (!r) return;
    if (r.error || r.errors?.length) return toast("Fix the items marked ✘ first", "bad");
    if (!r.diff && !this.cfBody()) return toast("No changes to apply", "");
    const v = r.validation;
    HPF._lastNote = "";
    const ok = await modal({ title: "Review and apply", size: "lg", body: `
      <ul class="plan">${r.plan.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>
      ${v ? `<div class="row">${pill(v.ok ? "ok" : "crit", v.ok ? "haproxy -c: valid" : "haproxy -c: invalid")}</div>${v.ok ? "" : `<pre class="out bad">${esc(v.output)}</pre>`}` : ""}
      ${renderDiff(r.diff)}
      <label class="f" style="margin-top:10px">Note for the activity log (optional)<input type="text" id="hpfNote" placeholder="why this change"></label>
      <div class="muted small">Applying: backup → write → reload → check HAProxy is still running → automatic rollback if not.</div>`,
      actions: [{ label: "Cancel", value: false }, ...(v && !v.ok ? [] : [{ label: "Apply", cls: "pri", value: true }])] });
    if (!ok) return;
    const note = HPF._lastNote || "";
    const res = await api(`/api/haproxy/${encodeURIComponent(F.node)}/apply`, { body: { ops: F.last.ops, cloudflare: this.cfBody(), base_hash: r.hash, note } });
    await showOutput(res.ok ? "Applied" : "Not applied", res);
    if (res.ok) {
      this.close(true);
      S.inv = await api("/api/inventory");
      refresh(true);
    } else this.runPreview();
  },
  async remove() {
    const F = this.F, kind = F.opts.kind, name = F.opts.name;
    const used = kind === "backend" ? (F.be.model.used_by || []) : [];
    if (used.length) return modal({ title: `Can't delete ${name} yet`, size: "sm", body: `<p>It's still used by <b>${esc(used.join(", "))}</b>. Change or remove those rules / default backend first.</p>`, actions: [{ label: "OK", value: true }] });
    if (!(await confirmBox(`Delete ${kind} ${name}?`, `<p>Removes the whole <code>${esc(kind)} ${esc(name)}</code> section from haproxy.cfg (a backup is kept, and it's reversible from Edit config → History).</p>`, "Review delete", "danger"))) return;
    F.fe.model = null; F.be.model = null;
    const ops = [{ op: "delete", kind, name }];
    const r = await api(`/api/haproxy/${encodeURIComponent(F.node)}/plan`, { body: { ops, validate: true } });
    if (r.error || r.errors?.length) return toast(r.error || r.errors.join("; "), "bad");
    const ok = await modal({ title: "Review delete", size: "lg", body: `${r.validation ? `<div class="row">${pill(r.validation.ok ? "ok" : "crit", r.validation.ok ? "haproxy -c: valid" : "haproxy -c: invalid")}</div>` : ""}${renderDiff(r.diff)}`,
      actions: [{ label: "Cancel", value: false }, { label: "Delete", cls: "danger", value: true }] });
    if (!ok) return this.close(true);
    const res = await api(`/api/haproxy/${encodeURIComponent(F.node)}/apply`, { body: { ops, base_hash: r.hash } });
    await showOutput(res.ok ? "Deleted" : "Not deleted", res);
    this.close(true);
    refresh(true);
  },

  /** quick change without opening the form (e.g. remove one server): review modal → apply */
  async quick(node, kind, name, mutate, title) {
    const d = await api(`/api/haproxy/${encodeURIComponent(node)}/model`);
    const m = (kind === "backend" ? d.backends : d.frontends).find((x) => x.name === name);
    if (!m) throw new Error(`${kind} ${name} not found`);
    mutate(m);
    const ops = [{ op: "upsert", kind, orig_name: name, model: m }];
    const r = await api(`/api/haproxy/${encodeURIComponent(node)}/plan`, { body: { ops, validate: true } });
    if (r.error || r.errors?.length) throw new Error(r.error || r.errors.join("; "));
    const ok = await modal({ title, size: "lg", body: `<ul class="plan">${r.plan.map((p) => `<li>${esc(p)}</li>`).join("")}</ul>${renderDiff(r.diff)}`,
      actions: [{ label: "Cancel", value: false }, { label: "Apply", cls: "pri", value: true }] });
    if (!ok) return;
    const res = await api(`/api/haproxy/${encodeURIComponent(node)}/apply`, { body: { ops, base_hash: r.hash } });
    if (res.ok) toast("Applied", "ok"); else await showOutput("Not applied", res);
    refresh(true);
  },
};

// keep the note typed in the review modal (the modal closes before apply runs)
document.addEventListener("input", (e) => { if (e.target.id === "hpfNote") HPF._lastNote = e.target.value; });
