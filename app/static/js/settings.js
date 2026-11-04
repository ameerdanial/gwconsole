/* Gateway Console web UI — Settings page (superadmin only), in sections: Access (users and sessions,
 * sign-in security), Connections (nodes with host-key confirmation and SSH test, Cloudflare accounts
 * with token permission test), Alerts (Telegram/Discord, Monitoring thresholds and weekly summary),
 * System (general, backups, config history, About & updates with release notes and update history). */
"use strict";

const ROLE_INFO = {
  viewer: "Viewer — sees everything, changes nothing",
  operator: "Operator — server state, reload/restart, configs, tunnels, hostnames, alerts",
  superadmin: "Superadmin — everything, including users and settings",
};
const yes = (ok) => `<span class="ck ${ok ? "ok" : "bad"}">${ok ? "✔" : "✘"}</span>`;
const checksHtml = (rows, nameKey) => `<ul class="checks">${rows.map((r) => `<li>${yes(r.ok)}<b>${esc(r[nameKey])}</b><span class="sub">${esc(r.detail)}</span></li>`).join("")}</ul>`;

PAGES.settings = {
  role: "superadmin",
  sections: [
    ["Access", [["users", "Users & sessions", "Who can sign in, their roles, and signed-in browsers"], ["signin", "Sign-in security", "Where sign-in is allowed from, two-step sign-in, and alerts about sign-ins", "new"]]],
    ["Connections", [["nodes", "Nodes", "The servers this dashboard manages and watches over SSH"], ["cloudflare", "Cloudflare accounts", "API tokens for tunnels, DNS and traffic numbers"]]],
    ["Alerts", [["notifications", "Notifications", "Telegram and Discord"], ["monitoring", "Monitoring", "How often things are checked, when an alert fires, and how long history is kept"]]],
    ["System", [["general", "General", "Dashboard address, alert history and config backups"], ["backups", "Backups", "Backups of this dashboard"], ["history", "Config history", "Every change to haproxy.cfg and tunnel configs"], ["about", "About & updates", "This dashboard's version, updates and release notes, and the software on your nodes"]]],
  ],
  get tabs() { return this.sections.flatMap(([, items]) => items); },
  mount(v, params) {
    this.tab = this.tabs.some((t) => t[0] === params[0]) ? params[0] : "users";
    const cur = this.tabs.find((t) => t[0] === this.tab);
    setHeader("Settings", "Superadmin · changes are recorded in Activity");
    v.innerHTML = `<div class="setgrid"><nav class="snav">${this.sections.map(([g, items]) => `<div class="g">${g}</div>` + items.map(([k, l, , nw]) =>
        `<a href="#/settings/${k}" class="${k === this.tab ? "on" : ""}" data-sk="${k}">${esc(l)}${nw ? `<span class="nw">${nw}</span>` : ""}</a>`).join("")).join("")}</nav>
      <div class="scol"><div class="sph"><h2>${esc(cur[1])}</h2><span class="sub">${esc(cur[2])}</span></div>
      <div id="setBody" class="scol"><div class="panel"><div class="empty">Loading…</div></div></div></div></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
    api("/api/system").then((d) => {
      const n = (d.update?.available || []).length;
      const a = $(`.snav [data-sk=about]`);
      if (a && n) a.insertAdjacentHTML("beforeend", `<span class="b">${n}</span>`);
    }).catch(() => {});
  },
  async load() { await this[this.tab](); },

  async onClick(e) {
    const b = e.target.closest("[data-a]");
    if (!b) return;
    const fn = this["act_" + b.dataset.a];
    if (fn) {
      try { await fn.call(this, b.dataset, b); } catch (err) { toast(err.message, "bad"); }
    }
  },

  // ============================================================ USERS
  async users() {
    const [u, s] = await Promise.all([api("/api/admin/users"), api("/api/admin/sessions")]);
    if (S.page !== "settings") return;
    this.cache = { users: u };
    $("#setBody").innerHTML = `
      <div class="panel"><div class="hd"><h2>Users</h2><span class="meta">${fmt.plural(u.items.length, "user")}</span>
        <div class="acts"><button class="btn sm pri" data-a="adduser">+ Add user</button></div></div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Can manage</th><th>2FA</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>
        ${u.items.map((x) => {
          const me = x.id === u.me;
          return `<tr class="${x.disabled ? "dim" : ""}"><td><b>${esc(x.username)}</b>${me ? ` <span class="tag">you</span>` : ""}</td>
            <td>${me ? pill("info", x.role) : `<select class="sm" data-userrole="${x.id}">${u.roles.map((r) => `<option ${r === x.role ? "selected" : ""}>${r}</option>`).join("")}</select>`}</td>
            <td>${x.role === "superadmin" || x.scope_mode !== "pick" ? `<span class="muted">everything</span>`
              : x.scope.slice(0, 2).map((i) => `<span class="chip">${esc(i.kind === "domain" ? i.ref : i.ref.split("/")[1])}</span>`).join("") + (x.scope.length > 2 ? `<span class="sub">+${x.scope.length - 2}</span>` : "")}</td>
            <td>${x.totp_on ? pill("ok", "on") : pill(x.role === "superadmin" ? "warn" : "mute", "off")}</td>
            <td>${x.disabled ? pill("mute", "disabled") : x.must_change ? pill("warn", "must change password") : pill("ok", "active")}</td>
            <td class="small nowrap">${x.last_login ? esc(fmt.ago(x.last_login)) : "never"}</td>
            <td><div class="row" style="justify-content:flex-end;flex-wrap:nowrap">${me ? `<a class="btn sm" href="#/account">My account</a>` : `
              ${x.role === "superadmin" ? "" : `<button class="btn sm" data-a="access" data-id="${x.id}" data-name="${esc(x.username)}">Access</button>`}
              ${x.totp_on ? `<button class="btn sm" data-a="reset2fa" data-id="${x.id}" data-name="${esc(x.username)}">Reset 2FA</button>` : ""}
              <button class="btn sm" data-a="resetpw" data-id="${x.id}" data-name="${esc(x.username)}">Reset password</button>
              <button class="btn sm" data-a="toggle" data-id="${x.id}" data-v="${x.disabled ? 0 : 1}">${x.disabled ? "Enable" : "Disable"}</button>
              <button class="btn sm danger" data-a="deluser" data-id="${x.id}" data-name="${esc(x.username)}">Delete</button>`}</div></td></tr>`;
        }).join("")}</tbody></table></div>
        <div class="bd small muted">${Object.values(ROLE_INFO).map(esc).join("<br>")}</div></div>
      <div class="panel"><div class="hd"><h2>Signed-in sessions</h2><span class="meta">${fmt.plural(s.items.length, "browser")} · grouped by user · revoking signs that browser out right away</span></div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>From</th><th>Browser</th><th>Last active</th><th>Expires</th><th></th></tr></thead><tbody>
        ${[...new Set(s.items.map((x) => x.username))].map((name) => {
          const all = s.items.filter((x) => x.username === name);
          const open = (this.sessOpen || {})[name], rows = open ? all : all.slice(0, 10);
          return `<tr class="dayh"><td colspan="5">${esc(name)} <span class="sub">${esc(all[0].role)} · ${fmt.plural(all.length, "browser")}</span></td></tr>`
            + rows.map((x) => `<tr><td class="mono small">${esc(x.ip || "")}</td>
              <td class="small" title="${esc(x.user_agent || "")}">${esc(uaShort(x.user_agent))}</td><td class="small nowrap">${esc(fmt.ago(x.last_active || x.last_seen))}</td>
              <td class="small nowrap">${esc(fmt.short(x.expires_at))}</td>
              <td>${x.sid === s.mine ? `<span class="tag">this browser</span>` : `<button class="btn sm" data-a="kick" data-sid="${esc(x.sid)}">Revoke</button>`}</td></tr>`).join("")
            + (all.length > 10 ? `<tr><td colspan="5"><button class="btn xs ghost" data-a="sessmore" data-name="${esc(name)}">${open ? "Show the newest 10" : `Show all ${all.length}`}</button></td></tr>` : "");
        }).join("")}
        </tbody></table></div></div>`;
    $$("[data-userrole]").forEach((sel) => sel.addEventListener("change", async () => {
      try { await api(`/api/admin/users/${sel.dataset.userrole}`, { method: "PATCH", body: { role: sel.value } }); toast("Role changed", "ok"); }
      catch (err) { toast(err.message, "bad"); }
      refresh(true);
    }));
  },
  async act_adduser() {
    const changed = await taskModal({
      title: "Add user", submit: "Create user",
      html: `<label>Username<input name="username" type="text" required autocomplete="off" placeholder="e.g. hafiz"></label>
        <label>Role<select name="role">${Object.entries(ROLE_INFO).map(([r, d]) => `<option value="${r}" ${r === "viewer" ? "selected" : ""}>${esc(d)}</option>`).join("")}</select></label>
        <label>Temporary password (optional)<input name="password" type="text" autocomplete="off" placeholder="leave empty to generate one">${PW_HINT}</label>
        <div class="note">They must choose their own password the first time they sign in.</div>`,
      run: async (fd) => {
        const r = await api("/api/admin/users", { body: fd });
        return { ok: true, output: `User ${fd.username} created.\n\nTemporary password (shown once, send it to them privately):\n\n    ${r.temp_password}` };
      },
    });
    if (changed) refresh(true);
  },
  // ---- scoped access: what a user can manage (tunnels, domains, extra HAProxy backends) ----
  async act_access(ds) {
    const [cur, ch] = await Promise.all([api(`/api/admin/users/${ds.id}/scope`), api("/api/admin/scope/choices")]);
    const st = { mode: cur.mode, items: cur.items.map((i) => ({ ...i })) };
    const has = (k, r) => st.items.some((i) => i.kind === k && i.ref === r);
    const toggle = (k, r, on) => { st.items = st.items.filter((i) => !(i.kind === k && i.ref === r)); if (on) st.items.push({ kind: k, ref: r }); };
    const w = document.createElement("div");
    w.className = "form";
    w.style.gap = "14px";
    const extra = ch.backends.filter((b) => !b.hosts.length);
    const draw = () => {
      const doms = st.items.filter((i) => i.kind === "domain");
      w.innerHTML = `<div class="row" style="gap:10px;flex-wrap:wrap"><span class="small muted">${esc(cur.user)} · ${esc(cur.role)} · can manage</span>
          <span class="segs" data-mode><button type="button" data-m="all" class="${st.mode === "all" ? "on" : ""}">Everything</button><button type="button" data-m="pick" class="${st.mode === "pick" ? "on" : ""}">Only what I pick</button></span>
          <span class="small muted" style="margin-left:auto">Takes effect on their next click.</span></div>
        ${st.mode === "all" ? `<div class="small muted">${esc(cur.user)} can manage everything a ${esc(cur.role)} can: every tunnel, hostname and backend.</div>` : `<div class="scopegrid"><div class="pickl">
          <div><h4>Tunnels · full control</h4><div class="box">${ch.tunnels.map((t) => `<label class="ln"><input type="checkbox" data-tun="${esc(t.ref)}" ${has("tunnel", t.ref) ? "checked" : ""}> ${esc(t.name)}
            <span class="sub mono">${esc(t.node)} · ${fmt.plural(t.hosts.length, "hostname")}${t.offline ? " · node not reachable now" : ""}</span></label>`).join("") || `<span class="muted small">No tunnels found.</span>`}</div>
            <div class="hint">Start/stop, logs, hostnames and the tunnel's config.</div></div>
          <div><h4>Domains · wherever they are</h4>
            <div class="chipin">${doms.map((d) => `<span class="c">${esc(d.ref)} <button type="button" data-rmdom="${esc(d.ref)}" title="Remove">✕</button></span>`).join("")}
              <input type="text" data-dom placeholder="add a domain or *.zone, then Enter" autocomplete="off"></div>
            <div class="zsug">${ch.zones.flatMap((z) => [`*.${z.zone}`, z.zone]).filter((z) => !has("domain", z)).slice(0, 12).map((z) => `<button type="button" data-adddom="${esc(z)}">+ ${esc(z)}</button>`).join("")}</div>
            <div class="hint">Their tunnel routes, DNS records, HAProxy host rules and the backends only they use. <span class="mono">*.example.com</span> doesn't include <span class="mono">example.com</span> itself.</div></div>
          <div><h4>Extra HAProxy backends</h4><div class="box">${extra.map((b) => `<label class="ln"><input type="checkbox" data-be="${esc(b.ref)}" ${has("backend", b.ref) ? "checked" : ""}> ${esc(b.name)}
            <span class="sub mono">${esc(b.node)}${b.default ? " · a default backend" : " · no hostname"}</span></label>`).join("") || `<span class="muted small">${ch.backends.some((b) => !b.offline) ? "Every backend is reached through a hostname." : "Couldn't read HAProxy right now."}</span>`}</div>
            <div class="hint">For backends no hostname points to (e.g. a TCP service).</div></div>
        </div><div class="prevw" data-prev><div class="muted small">Pick something to see what ${esc(cur.user)} gets.</div></div></div>`}`;
      preview();
    };
    let t = 0;
    const preview = () => {
      clearTimeout(t);
      const box = $("[data-prev]", w);
      if (!box || !st.items.length) return;
      t = setTimeout(async () => {
        try {
          const p = await api("/api/admin/scope/preview", { body: { items: st.items } });
          box.innerHTML = `<div><h4>What ${esc(cur.user)} gets</h4><div class="small muted">Everything else is hidden from them.</div></div>
            ${p.tunnels.length ? `<div><h4>Tunnels</h4><ul>${p.tunnels.map((x) => `<li>${esc(x.split("/")[1])}<span class="sub mono">${esc(x.split("/")[0])} · restart, config, logs</span></li>`).join("")}</ul></div>` : ""}
            <div><h4>Hostnames · ${p.hosts.length}</h4><ul>${p.hosts.slice(0, 14).map((h) => `<li><span class="mono">${esc(h.host)}</span><span class="sub">${h.route_only ? "route only · " : ""}${esc(h.via)}</span></li>`).join("") || `<li class="muted">none yet</li>`}
              ${p.hosts.length > 14 ? `<li class="muted">+${p.hosts.length - 14} more</li>` : ""}</ul></div>
            ${p.haproxy.map((n) => `<div><h4>HAProxy · ${esc(n.node)}</h4><ul>${n.frontends.map((f) => `<li><span class="mono">${esc(f.name)}</span><span class="sub">${fmt.plural(f.rules, "host rule")} · listen & TLS <span class="lockt">🔒 locked</span></span></li>`).join("")}
              ${n.own.map((b) => `<li><span class="mono">${esc(b)}</span><span class="sub">servers · drain, maint, edit</span></li>`).join("")}
              ${n.shared.map((b) => `<li><span class="mono">${esc(b)}</span><span class="sub"><span class="lockt">🔒 shared</span> read-only</span></li>`).join("")}</ul></div>`).join("")}
            <div><h4>Also</h4><ul><li>${fmt.plural(p.checks, "monitoring check")} · ${fmt.plural(p.alerts, "open alert")}</li></ul></div>
            <div class="small muted">Not allowed: the whole-file HAProxy editor, HAProxy reload/restart, new or deleted tunnels, Settings.</div>`;
        } catch (err) { box.innerHTML = `<div class="ferr">${esc(err.message)}</div>`; }
      }, 250);
    };
    const addDom = (v) => {
      v = String(v || "").trim().toLowerCase().replace(/\.$/, "");
      if (v && !has("domain", v)) toggle("domain", v, true);
      draw();
      $("[data-dom]", w)?.focus();
    };
    w.addEventListener("click", (e) => {
      const m = e.target.closest("[data-m]");
      if (m) { st.mode = m.dataset.m; return draw(); }
      const rd = e.target.closest("[data-rmdom]");
      if (rd) { toggle("domain", rd.dataset.rmdom, false); return draw(); }
      const ad = e.target.closest("[data-adddom]");
      if (ad) return addDom(ad.dataset.adddom);
    });
    w.addEventListener("change", (e) => {
      if (e.target.dataset.tun) { toggle("tunnel", e.target.dataset.tun, e.target.checked); preview(); }
      if (e.target.dataset.be) { toggle("backend", e.target.dataset.be, e.target.checked); preview(); }
    });
    w.addEventListener("keydown", (e) => {
      if (e.target.matches("[data-dom]") && (e.key === "Enter" || e.key === ",")) { e.preventDefault(); addDom(e.target.value); }
    });
    draw();
    const ok = await modal({ title: `Access for ${cur.user}`, size: "lg", body: w, actions: [{ label: "Cancel", value: false }, { label: "Save access", cls: "pri", value: true }] });
    if (!ok) return;
    const pending = $("[data-dom]", w)?.value;
    if (pending) addDom(pending);
    try {
      await api(`/api/admin/users/${ds.id}/scope`, { method: "PUT", body: { mode: st.mode, items: st.mode === "pick" ? st.items : [] } });
      toast(st.mode === "all" ? `${cur.user} can manage everything again` : `Saved what ${cur.user} can manage`, "ok");
    } catch (err) { toast(err.message, "bad"); }
    this.users();
  },
  async act_reset2fa(ds) {
    if (!(await confirmBox(`Reset two-step sign-in for ${ds.name}?`, `<p>Use this when ${esc(ds.name)} lost their phone. Two-step sign-in is turned off and their browsers are signed out.
      If their role requires it, they set it up again with a new phone right after signing in.</p>`, "Reset 2FA", "danger"))) return;
    try { await api(`/api/admin/users/${ds.id}/2fa/reset`, { body: {} }); toast(`Two-step sign-in reset for ${ds.name}`, "ok"); }
    catch (err) { toast(err.message, "bad"); }
    this.users();
  },
  async act_resetpw(ds) {
    if (!(await confirmBox(`Reset ${ds.name}'s password?`, "<p>They are signed out everywhere and must choose a new password with the temporary one.</p>", "Reset"))) return;
    const r = await api(`/api/admin/users/${ds.id}/reset`, { body: {} });
    await modal({ title: "Temporary password", body: `<p style="margin:0">Send this to <b>${esc(ds.name)}</b> privately. It is shown only once.</p><pre class="out ok">${esc(r.temp_password)}</pre>`, actions: [{ label: "Done", value: true }] });
    refresh(true);
  },
  async act_toggle(ds) {
    await api(`/api/admin/users/${ds.id}`, { method: "PATCH", body: { disabled: ds.v === "1" } });
    refresh(true);
  },
  async act_deluser(ds) {
    if (!(await confirmBox(`Delete ${ds.name}?`, "<p>The account is removed. Their past actions stay in the Activity log.</p>", "Delete", "danger"))) return;
    await api(`/api/admin/users/${ds.id}`, { method: "DELETE" });
    refresh(true);
  },
  async act_mypw() { await changePassword(false); },
  async act_kick(ds) {
    await api(`/api/admin/sessions/${ds.sid}`, { method: "DELETE" });
    toast("Session revoked", "ok"); refresh(true);
  },

  // ============================================================ CLOUDFLARE
  async cloudflare() {
    const d = await api("/api/admin/cf-accounts");
    if (S.page !== "settings") return;
    this.cache = { cf: d.items };
    $("#setBody").innerHTML = `
      <div class="panel"><div class="hd"><h2>Cloudflare accounts</h2><span class="meta">One entry per Cloudflare login. Tunnels are matched to their account automatically.</span>
        <div class="acts"><button class="btn sm pri" data-a="addcf">+ Add account</button></div></div>
        <div class="bd"><div class="cards">${d.items.map((a) => `<div class="card">
          <div class="t">${esc(a.name)}<span class="r">${a.has_token ? pill("ok", "token saved") : pill("crit", "no token")}</span></div>
          <dl class="kv"><dt>Account ID</dt><dd class="mono small">${esc(a.account_id)}</dd><dt>Updated</dt><dd>${esc(fmt.ago(a.updated_at))}</dd></dl>
          <div class="cfres" data-res="${esc(a.name)}"></div>
          <div class="row"><button class="btn sm" data-a="testcf" data-name="${esc(a.name)}">Test token</button>
            <button class="btn sm" data-a="editcf" data-name="${esc(a.name)}">Edit</button><span class="grow"></span>
            <button class="btn sm danger" data-a="delcf" data-name="${esc(a.name)}">Delete</button></div></div>`).join("") || `<div class="empty">No accounts yet. Add one to see tunnel health and manage DNS.</div>`}</div></div></div>
      <div class="panel"><div class="hd"><h2>Where to find these</h2></div><div class="bd small help">
        <p><b>Account ID</b>: open <code>dash.cloudflare.com</code> → click one of your domains → scroll the right-hand column to the <b>API</b> box → <b>Account ID</b>. It is also the long code in the address bar: <code>dash.cloudflare.com/<b>3f8a91…</b>/home</code>.</p>
        <p><b>API token</b>: person icon (top right) → <b>Profile</b> → <b>API Tokens</b> → <b>Create Token</b> → <b>Create Custom Token</b>, with these permissions:</p>
        <table class="mini-t"><tr><td>Account</td><td>Cloudflare Tunnel</td><td>Edit</td></tr><tr><td>Zone</td><td>Zone</td><td>Read</td></tr><tr><td>Zone</td><td>DNS</td><td>Edit</td></tr><tr><td>Zone</td><td>Analytics</td><td>Read</td></tr></table>
        <p>Account Resources: your account · Zone Resources: All zones. Use <b>Test token</b> to confirm.</p></div></div>`;
  },
  cfForm(a) {
    return `<label>Name<input name="name" type="text" required value="${esc(a?.name || "")}" placeholder="main"><div class="hint">Any label, e.g. main, kodje</div></label>
      <label>Account ID<input name="account_id" type="text" required value="${esc(a?.account_id || "")}" placeholder="32-character code" class="mono"></label>
      <label>API token<input name="token" type="password" ${a ? "" : "required"} autocomplete="off" placeholder="${a ? "leave empty to keep the saved token" : "paste the token"}"></label>
      <div class="row"><button type="button" class="btn sm" data-cftest>Test before saving</button><span class="muted small">Checks the token's permissions without changing anything.</span></div>
      <div data-cfresult></div>`;
  },
  cfFormOpen(orig) {
    return (f) => $("[data-cftest]", f).addEventListener("click", async (e) => {
      const fd = Object.fromEntries(new FormData(f).entries());
      const box = $("[data-cfresult]", f);
      box.innerHTML = `<div class="muted small">Testing…</div>`;
      busy(e.target, true);
      try {
        const body = fd.token ? { account_id: fd.account_id, token: fd.token } : { name: orig, account_id: fd.account_id };
        const r = await api("/api/admin/cf-accounts/test", { body });
        box.innerHTML = checksHtml(r.results, "perm");
      } catch (err) { box.innerHTML = `<div class="out bad">${esc(err.message)}</div>`; } finally { busy(e.target, false); }
    });
  },
  async act_addcf() {
    const changed = await taskModal({
      title: "Add Cloudflare account", submit: "Save account", size: "", html: this.cfForm(null), onOpen: this.cfFormOpen(null),
      run: (fd) => api("/api/admin/cf-accounts", { body: fd }).then(() => ({ ok: true, output: `Account ${fd.name} saved. The token is stored encrypted.` })),
    });
    if (changed) { S.inv = await api("/api/inventory"); refresh(true); }
  },
  async act_editcf(ds) {
    const a = this.cache.cf.find((x) => x.name === ds.name);
    const changed = await taskModal({
      title: `Edit ${ds.name}`, submit: "Save", size: "", html: this.cfForm(a), onOpen: this.cfFormOpen(ds.name),
      run: (fd) => api(`/api/admin/cf-accounts/${encodeURIComponent(ds.name)}`, { method: "PUT", body: fd }).then(() => ({ ok: true, output: "Saved." })),
    });
    if (changed) { S.inv = await api("/api/inventory"); refresh(true); }
  },
  async act_testcf(ds, btn) {
    const box = $(`[data-res="${CSS.escape(ds.name)}"]`);
    box.innerHTML = `<div class="muted small">Testing…</div>`;
    busy(btn, true);
    try { box.innerHTML = checksHtml((await api("/api/admin/cf-accounts/test", { body: { name: ds.name } })).results, "perm"); }
    catch (err) { box.innerHTML = `<div class="out bad">${esc(err.message)}</div>`; } finally { busy(btn, false); }
  },
  async act_delcf(ds) {
    if (!(await confirmBox(`Delete account ${ds.name}?`, "<p>Only removes it from the dashboard. Nothing changes in Cloudflare.</p>", "Delete", "danger"))) return;
    await api(`/api/admin/cf-accounts/${encodeURIComponent(ds.name)}`, { method: "DELETE" });
    S.inv = await api("/api/inventory"); refresh(true);
  },

  // ============================================================ NODES
  async nodes() {
    const d = await api("/api/admin/nodes");
    if (S.page !== "settings") return;
    this.cache = { nodes: d.items, pubkey: d.pubkey };
    const ipHint = /^\d+\.\d+\.\d+\.\d+$/.test(location.hostname) ? location.hostname : "<this-dashboard-ip>";
    $("#setBody").innerHTML = `
      ${d.imported && (d.imported.users || d.imported.nodes || d.imported.cf_accounts) ? `<div class="panel"><div class="bd small muted">Imported from <code>config.yaml</code> on ${esc(fmt.time(d.imported.at))}
        (${fmt.plural(d.imported.users, "user")}, ${fmt.plural(d.imported.nodes, "node")}, ${fmt.plural(d.imported.cf_accounts, "account")}). Those entries in config.yaml are ignored now — manage everything here.</div></div>` : ""}
      <div class="panel"><div class="hd"><h2>Nodes</h2><span class="meta">The servers this dashboard manages over SSH.</span>
        <div class="acts"><button class="btn sm pri" data-a="addnode">+ Add node</button></div></div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Address</th><th>SSH user</th><th>Host key</th><th></th></tr></thead><tbody>
        ${d.items.map((n) => `<tr><td><b>${esc(n.name)}</b>${n.site ? ` <span class="tag">${esc(n.site)}</span>` : ""}</td>
          <td>${{ haproxy: "HAProxy", cloudflared: "cloudflared", server: "Server" }[n.kind] || esc(n.kind)}</td><td class="mono small">${esc(n.host)}:${n.port}</td>
          <td class="mono small">${esc(n.user)}${n.sudo ? " + sudo" : ""}</td>
          <td class="small">${n.host_key ? `<span class="mono" title="${esc(n.host_key)}">${esc(n.host_key.split(" ")[0])} pinned</span>` : `<span class="muted">known_hosts file</span>`}</td>
          <td><div class="row" style="justify-content:flex-end;flex-wrap:nowrap"><button class="btn sm" data-a="testnode" data-name="${esc(n.name)}">Test</button>
            <button class="btn sm" data-a="editnode" data-name="${esc(n.name)}">Edit</button>
            <button class="btn sm danger" data-a="delnode" data-name="${esc(n.name)}">Delete</button></div></td></tr>
          <tr class="hidden" data-testrow="${esc(n.name)}"><td colspan="6"></td></tr>`).join("") || `<tr><td colspan="6" class="empty">No nodes yet.</td></tr>`}
        </tbody></table></div></div>
      <div class="panel"><div class="hd"><h2>How adding a node works</h2></div><div class="bd small help">
        <p>Any Linux host with SSH works — a VM, an LXC or bare metal. Click <b>+ Add node</b>, enter its address, <b>scan</b> and confirm the host key, then either:</p>
        <p>• <b>Use the node's password once</b> — the dashboard logs in one time, installs its SSH key (accepted only from this dashboard), <code>socat</code> and HAProxy's admin socket, then forgets the password. Or</p>
        <p>• <b>Run a command on the node</b> yourself, as root:</p>
        <pre class="out" id="prepCmd">${esc(this.prepCmd(d.pubkey, ipHint))}</pre>
        <div class="row"><button class="btn sm" data-a="copy" data-target="prepCmd">Copy command</button><span class="muted">${ipHint.startsWith("<") ? "Put this dashboard's IP after --from." : `--from is the address the node sees this dashboard as; the Add node form fills it in exactly.`}</span></div></div></div>`;
  },
  prepCmd(pubkey, fromIp) {
    return `curl -fsSL ${location.origin}/prepare-node.sh | bash -s -- --key "${pubkey}" --from ${fromIp}`;
  },
  nodeForm(n) {
    const k = n?.kind || "haproxy";
    const v = (f, def) => esc(n?.[f] ?? def);
    return `<div class="two"><label>Type<select name="kind" ${n ? "disabled" : ""}><option value="haproxy" ${k === "haproxy" ? "selected" : ""}>HAProxy</option><option value="cloudflared" ${k === "cloudflared" ? "selected" : ""}>cloudflared</option><option value="server" ${k === "server" ? "selected" : ""}>Server (health and services only)</option></select></label>
        <label>Name<input name="name" type="text" required value="${v("name", "")}" placeholder="haproxy-dr"></label></div>
      <div class="two"><label>Host (IP or hostname)<input name="host" type="text" required value="${v("host", "")}" placeholder="192.168.20.10"></label>
        <label>SSH port<input name="port" type="text" value="${v("port", 22)}"></label></div>
      <div class="two"><label data-manual class="${n ? "" : "hidden"}">SSH user<input name="user" type="text" value="${v("user", "root")}"></label>
        <label>Site label (optional)<input name="site" type="text" value="${v("site", "")}" placeholder="DC1 / DR"></label></div>
      <label class="check ${n ? "" : "hidden"}" data-manual><input type="checkbox" name="sudo" ${n?.sudo ? "checked" : ""}> Not root: use <code>sudo</code> (user needs passwordless sudo)</label>
      <details ${n ? "" : ""}><summary>Paths &amp; service names</summary><div style="margin-top:10px;display:flex;flex-direction:column;gap:10px">
        <div data-k="haproxy" class="${k === "haproxy" ? "" : "hidden"}"><div class="two">
          <label>haproxy.cfg<input name="config_path" type="text" value="${v("config_path", "/etc/haproxy/haproxy.cfg")}"></label>
          <label>Admin stats socket<input name="stats_socket" type="text" value="${v("stats_socket", "/run/haproxy/admin.sock")}"></label></div>
          <div class="two" style="margin-top:10px"><label>Backup folder<input name="backup_dir" type="text" value="${v("backup_dir", "/etc/haproxy/gwc-backups")}"></label>
          <label>systemd service<input name="service" type="text" value="${v("service", "haproxy")}"></label></div></div>
        <div data-k="cloudflared" class="${k === "cloudflared" ? "" : "hidden"}"><div class="two">
          <label>Folder for new tunnels<input name="tunnel_base_dir" type="text" value="${v("tunnel_base_dir", "/root/.cloudflared")}"></label>
          <label>cloudflared binary<input name="cloudflared_bin" type="text" value="${v("cloudflared_bin", "cloudflared")}"></label></div>
          <label class="check" style="margin-top:10px"><input type="checkbox" name="discover" ${n ? (n.discover ? "checked" : "") : "checked"}> Auto-discover cloudflared services</label></div>
        <div data-k="server" class="${k === "server" ? "" : "hidden"} small muted">Nothing to set for a server: CPU load, memory, disks and uptime are read over SSH. Choose services to watch on the Monitoring page.</div>
      </div></details>
      <div class="sep">Host key</div>
      <input type="hidden" name="host_key" value="${v("host_key", "")}">
      <div data-hk class="small">${n?.host_key ? `Pinned: <span class="mono">${esc(n.host_key.slice(0, 60))}…</span>` : `<span class="muted">Not scanned yet.</span>`}</div>
      <div class="row"><button type="button" class="btn sm" data-scan>Scan host key</button><button type="button" class="btn sm" data-ntest>Test connection</button></div>
      <label class="check hidden" data-confirmrow><input type="checkbox" name="hk_ok"> I checked this fingerprint against the node (<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>)</label>
      <div data-ntestres></div>
      <div class="sep">Access</div>
      <div class="radios">
        ${n ? `<label class="check"><input type="radio" name="access" value="keep" checked> Already set up</label>` : ""}
        <label class="check"><input type="radio" name="access" value="password" ${n ? "" : "checked"}> Use the node's password once <span class="muted">— easiest</span></label>
        <label class="check"><input type="radio" name="access" value="command"> I'll run a command on the node</label>
      </div>
      <div data-acc="password" class="${n ? "hidden" : ""}">
        <div class="two"><label>Log in as<input name="bs_login" type="text" value="root" autocomplete="off"></label>
          <label>Password<input name="bs_password" type="password" autocomplete="new-password"></label></div>
        <div class="hint">Used once to install this dashboard's SSH key — accepted only from this dashboard — then forgotten: never stored or logged.
          Debian and Ubuntu block root password logins by default; enter a sudo user there and the dashboard still connects as root with its key
          (or as that user with sudo, if root can't log in over SSH at all).</div>
        <label class="check ${k === "haproxy" ? "" : "hidden"}" data-k="haproxy" style="margin-top:8px"><input type="checkbox" name="bs_fix" checked> Set up HAProxy's admin stats socket and <code>socat</code> if missing</label>
      </div>
      <div data-acc="command" class="hidden">
        <div class="hint">Run this as root on the node (it asks nothing else), then press Save:</div>
        <pre class="out" data-cmd style="margin-top:6px"></pre>
        <div class="row"><button type="button" class="btn sm" data-copycmd>Copy</button><span class="muted small" data-cmdnote></span></div>
      </div>`;
  },
  nodeFormOpen(orig) {
    return (f) => {
      const kindSel = $("[name=kind]", f);
      kindSel.addEventListener("change", () => $$("[data-k]", f).forEach((x) => x.classList.toggle("hidden", x.dataset.k !== kindSel.value)));
      const vals = () => {
        const fd = Object.fromEntries(new FormData(f).entries());
        fd.kind = kindSel.value; fd.sudo = $("[name=sudo]", f).checked; fd.discover = $("[name=discover]", f).checked;
        fd.port = +fd.port || 22;
        return fd;
      };
      let fromIp = /^\d+\.\d+\.\d+\.\d+$/.test(location.hostname) ? location.hostname : "";
      const cmd = () => {
        $("[data-cmd]", f).textContent = this.prepCmd(this.cache?.pubkey || "<gwconsole pubkey>", fromIp || "<this-dashboard-ip>");
        $("[data-cmdnote]", f).textContent = fromIp ? `${fromIp} = this dashboard as the node sees it` : "scan the host key first to fill in this dashboard's IP";
      };
      cmd();
      $$("[name=access]", f).forEach((r) => r.addEventListener("change", () => {
        const a = $("[name=access]:checked", f).value;
        $$("[data-acc]", f).forEach((x) => x.classList.toggle("hidden", x.dataset.acc !== a));
        $$("[data-manual]", f).forEach((x) => x.classList.toggle("hidden", a === "password"));   // set automatically
        $("[data-submit]", f.closest("form") || f).textContent = a === "password" ? "Set up & save" : "Save node";
      }));
      $("[data-copycmd]", f).addEventListener("click", async () => {
        try { await navigator.clipboard.writeText($("[data-cmd]", f).textContent); toast("Copied", "ok"); } catch { toast("Select the text and copy it manually", "bad"); }
      });
      $("[data-scan]", f).addEventListener("click", async (e) => {
        const fd = vals();
        busy(e.target, true);
        try {
          const r = await api("/api/admin/nodes/scan", { body: { host: fd.host, port: fd.port } });
          if (r.from_ip) { fromIp = r.from_ip; cmd(); }
          $("[name=host_key]", f).value = r.key;
          $("[data-hk]", f).innerHTML = `<div class="fp"><b>${esc(r.type)}</b> <span class="mono">${esc(r.fingerprint)}</span></div>`;
          $("[data-confirmrow]", f).classList.remove("hidden");
          $("[name=hk_ok]", f).checked = false;
        } catch (err) { $("[data-hk]", f).innerHTML = `<span style="color:var(--crit)">${esc(err.message)}</span>`; } finally { busy(e.target, false); }
      });
      $("[data-ntest]", f).addEventListener("click", async (e) => {
        const box = $("[data-ntestres]", f);
        box.innerHTML = `<div class="muted small">Testing…</div>`;
        busy(e.target, true);
        try { box.innerHTML = checksHtml((await api("/api/admin/nodes/test", { body: { ...vals(), original: orig || "" } })).checks, "check"); }
        catch (err) { box.innerHTML = `<div class="out bad">${esc(err.message)}</div>`; } finally { busy(e.target, false); }
      });
    };
  },
  nodeSubmit(orig) {
    return async (fd, f) => {
      // fd was captured by taskModal before the inputs were disabled
      const v = { ...fd, kind: $("[name=kind]", f).value, port: +fd.port || 22 };
      const confirmRow = $("[data-confirmrow]", f);
      if (!confirmRow.classList.contains("hidden") && !fd.hk_ok) throw new Error("tick the box to confirm the host key fingerprint");
      if (!orig && !v.host_key) throw new Error("scan the host key first");
      const access = fd.access || "keep", out = [];
      ["hk_ok", "access", "bs_login", "bs_password", "bs_fix"].forEach((x) => delete v[x]);
      if (access === "password") {
        if (!v.host_key) throw new Error("scan and confirm the host key first");
        if (!fd.bs_password) throw new Error("enter the node's password (or pick another access option)");
        const b = await api("/api/admin/nodes/bootstrap", { body: { host: v.host, port: v.port, login: fd.bs_login || "root",
          password: fd.bs_password, host_key: v.host_key, fix_socket: v.kind === "haproxy" ? !!fd.bs_fix : false } });
        if (!b.ok) throw new Error(`${b.error}\n\n${b.output}`);
        Object.assign(v, b.node);
        if (v.kind === "haproxy" && b.found?.haproxy === "0") out.push("⚠ haproxy isn't installed on this node yet");
        if (v.kind === "cloudflared" && b.found?.cloudflared === "0") out.push("⚠ cloudflared isn't installed on this node yet");
        out.push(`✔ SSH key installed for ${b.node.user} (accepted only from ${b.from_ip}); the password was not kept`);
      }
      if (orig) await api(`/api/admin/nodes/${encodeURIComponent(orig)}`, { method: "PUT", body: v });
      else await api("/api/admin/nodes", { body: v });
      out.push(`✔ node ${v.name} saved`);
      let ok = true;
      try {
        const t = await api("/api/admin/nodes/test", { body: { name: v.name } });
        out.push("", "Connection test:", ...t.checks.map((c) => `${c.ok ? "✔" : "✘"} ${c.check} — ${c.detail}`));
        ok = t.checks.every((c) => c.ok);
        if (!ok) out.push("", access === "command" ? "Run the command on the node, then use Test in the node list."
          : "Fix what's marked ✘ (Test in the node list re-checks; a missing stats socket has a 'Fix it' button there).");
      } catch (err) { ok = false; out.push(`✘ test failed: ${err.message}`); }
      return { ok, output: out.join("\n") };
    };
  },
  async act_addnode() {
    const changed = await taskModal({ title: "Add node", submit: "Set up & save", size: "", html: this.nodeForm(null),
      onOpen: this.nodeFormOpen(null), run: this.nodeSubmit(null) });
    if (changed) { S.inv = await api("/api/inventory"); refresh(true); }
  },
  async act_editnode(ds) {
    const n = this.cache.nodes.find((x) => x.name === ds.name);
    const changed = await taskModal({ title: `Edit ${ds.name}`, submit: "Save", size: "", html: this.nodeForm(n),
      onOpen: this.nodeFormOpen(ds.name), run: this.nodeSubmit(ds.name) });
    if (changed) { S.inv = await api("/api/inventory"); refresh(true); }
  },
  async act_testnode(ds, btn) {
    const row = $(`[data-testrow="${CSS.escape(ds.name)}"]`);
    row.classList.remove("hidden");
    const td = $("td", row) || row;
    td.innerHTML = `<div class="muted small">Testing…</div>`;
    busy(btn, true);
    try {
      const r = await api("/api/admin/nodes/test", { body: { name: ds.name } });
      const sockBad = r.checks.some((c) => !c.ok && (c.check === "admin stats socket" || c.check === "socat"));
      td.innerHTML = checksHtml(r.checks, "check") +
        (sockBad ? `<div class="row" style="margin-top:6px"><button class="btn sm pri" data-a="fixsock" data-name="${esc(ds.name)}">Fix it: set up the stats socket &amp; socat</button></div>` : "");
    }
    catch (err) { td.innerHTML = `<div class="out bad">${esc(err.message)}</div>`; } finally { busy(btn, false); }
  },
  async act_fixsock(ds, btn) {
    busy(btn, true);
    try { if (await fixStatsSocket(ds.name)) await this.act_testnode(ds, $(`[data-a=testnode][data-name="${CSS.escape(ds.name)}"]`)); }
    finally { busy(btn, false); }
  },
  async act_delnode(ds) {
    if (!(await confirmBox(`Remove node ${ds.name}?`, "<p>The dashboard stops managing it. Nothing changes on the node itself.</p>", "Remove", "danger"))) return;
    await api(`/api/admin/nodes/${encodeURIComponent(ds.name)}`, { method: "DELETE" });
    S.inv = await api("/api/inventory"); refresh(true);
  },
  async act_copy(ds) {
    const t = $("#" + ds.target).textContent;
    try { await navigator.clipboard.writeText(t); toast("Copied", "ok"); } catch { toast("Select the text and copy it manually", "bad"); }
  },

  // ============================================================ NOTIFICATIONS
  async notifications(box) {
    box = box || $("#setBody");
    const d = await api("/api/admin/notify");
    if (!box.isConnected) return;
    const st = (ch) => {
      const s = d.status[ch];
      if (!s) return `<span class="muted">Nothing sent yet.</span>`;
      return s.ok ? `${yes(true)} last sent ${esc(fmt.ago(s.at))} (${s.sent} change(s))` : `${yes(false)} last attempt ${esc(fmt.ago(s.at))}: ${esc(s.error)}`;
    };
    const sev = (v) => `<select name="min_severity"><option value="warn" ${v === "warn" ? "selected" : ""}>Warnings and critical</option><option value="crit" ${v === "crit" ? "selected" : ""}>Critical only</option></select>`;
    const tg = d.telegram, dc = d.discord;
    box.innerHTML = `
      <div class="grid2">
      <form class="panel form-panel" data-ch="telegram"><div class="hd"><h2>Telegram</h2>${tg.enabled ? pill("ok", "on") : pill("mute", "off")}</div><div class="bd form">
        <label class="check"><input type="checkbox" name="enabled" ${tg.enabled ? "checked" : ""}> Send alerts to Telegram</label>
        <label>Bot token<input name="bot_token" type="password" autocomplete="off" placeholder="${tg.has_bot_token ? "saved — leave empty to keep" : "123456789:AA…"}"></label>
        <label>Chat ID<input name="chat_id" type="text" value="${esc(tg.chat_id)}" placeholder="123456789 or -100… for a group"></label>
        <div class="two"><label>Send${sev(tg.min_severity)}</label><label class="check" style="align-self:end"><input type="checkbox" name="recoveries" ${tg.recoveries ? "checked" : ""}> Also send recoveries</label></div>
        <div class="row"><button type="button" class="btn sm pri" data-save>Save</button><button type="button" class="btn sm" data-test>Send test</button><span class="grow"></span></div>
        <div class="small" data-st>${st("telegram")}</div>
        <details class="small help"><summary>How to get these</summary>
          <p>1. In Telegram, message <b>@BotFather</b> → <code>/newbot</code> → copy the <b>bot token</b>.</p>
          <p>2. Send any message to your new bot (or add it to a group).</p>
          <p>3. Message <b>@userinfobot</b> to get your <b>chat ID</b> (for a group, add <b>@RawDataBot</b> to the group; the ID starts with -100).</p></details>
      </div></form>
      <form class="panel form-panel" data-ch="discord"><div class="hd"><h2>Discord</h2>${dc.enabled ? pill("ok", "on") : pill("mute", "off")}</div><div class="bd form">
        <label class="check"><input type="checkbox" name="enabled" ${dc.enabled ? "checked" : ""}> Send alerts to Discord</label>
        <label>Webhook URL<input name="webhook" type="password" autocomplete="off" placeholder="${dc.has_webhook ? "saved — leave empty to keep" : "https://discord.com/api/webhooks/…"}"></label>
        <div class="two"><label>Send${sev(dc.min_severity)}</label><label class="check" style="align-self:end"><input type="checkbox" name="recoveries" ${dc.recoveries ? "checked" : ""}> Also send recoveries</label></div>
        <div class="row"><button type="button" class="btn sm pri" data-save>Save</button><button type="button" class="btn sm" data-test>Send test</button><span class="grow"></span></div>
        <div class="small" data-st>${st("discord")}</div>
        <details class="small help"><summary>How to get the webhook</summary>
          <p>In Discord: channel <b>⚙ Edit Channel</b> → <b>Integrations</b> → <b>Webhooks</b> → <b>New Webhook</b> → <b>Copy Webhook URL</b>.</p></details>
      </div></form></div>
      <div class="panel"><div class="bd small muted">Messages are sent only when an alert starts, escalates or resolves — never repeated while it keeps firing, and never for muted alerts.
        Several changes in one check are combined into one message. ${d.dashboard_url ? `Messages link to <span class="mono">${esc(d.dashboard_url)}</span>.` : `Set the <a href="#/settings/general">dashboard URL</a> to get a link in each message.`}</div></div>`;
    $$("form[data-ch]", box).forEach((form) => {
      const ch = form.dataset.ch;
      const vals = () => {
        const fd = Object.fromEntries(new FormData(form).entries());
        ["enabled", "recoveries"].forEach((k) => (fd[k] = $(`[name=${k}]`, form).checked));
        if (!fd.bot_token) delete fd.bot_token;
        if (!fd.webhook) delete fd.webhook;
        return fd;
      };
      form.addEventListener("submit", (e) => e.preventDefault());
      $("[data-save]", form).addEventListener("click", async (e) => {
        busy(e.target, true);
        try { await api(`/api/admin/notify/${ch}`, { method: "PUT", body: vals() }); toast(`${ch} saved`, "ok"); this.notifications(box); }
        catch (err) { toast(err.message, "bad"); } finally { busy(e.target, false); }
      });
      $("[data-test]", form).addEventListener("click", async (e) => {
        busy(e.target, true);
        const box = $("[data-st]", form);
        try {
          const r = await api(`/api/admin/notify/${ch}/test`, { body: vals() });
          box.innerHTML = r.ok ? `${yes(true)} Test message sent — check ${ch}.` : `${yes(false)} ${esc(r.error)}`;
        } catch (err) { box.innerHTML = `${yes(false)} ${esc(err.message)}`; } finally { busy(e.target, false); }
      });
    });
  },

  // ============================================================ GENERAL
  async general() {
    const d = await api("/api/admin/general");
    if (S.page !== "settings") return;
    const g = d.settings;
    $("#setBody").innerHTML = `
      <form class="panel" id="genForm"><div class="hd"><h2>General</h2></div><div class="bd form" style="max-width:680px">
        <label>Dashboard URL<input name="dashboard_url" type="text" value="${esc(g.dashboard_url)}" placeholder="http://192.168.10.50:8088"><div class="hint">Used for links in Telegram/Discord messages.</div></label>
        <div class="two"><label>Check alerts every (seconds)<input name="alert_interval" type="text" value="${g.alert_interval}"></label>
          <label>Keep alert history (days)<input name="alert_retention_days" type="text" value="${g.alert_retention_days}"></label></div>
        <div class="two"><label>Config backups kept per file<input name="keep_backups" type="text" value="${g.keep_backups}"></label><span></span></div>
        <label class="check"><input type="checkbox" name="drift_check" ${g.drift_check ? "checked" : ""}> Alert when a config file is changed outside the dashboard (checked every 15 minutes)</label>
        <div class="row"><button class="btn pri" type="submit">Save</button><span class="grow"></span><a class="btn" href="#/setup">Run the setup wizard again</a></div></div></form>
      <div class="panel"><div class="hd"><h2>System</h2></div><div class="bd"><dl class="kv">
        <dt>Database</dt><dd class="mono small">${esc(d.db_path)}</dd>
        <dt>Alert checker</dt><dd>${d.engine.last_run ? `last run ${esc(fmt.ago(d.engine.last_run))}` : "not run yet"}${d.engine.last_error ? ` · <span style="color:var(--crit)">${esc(d.engine.last_error)}</span>` : ""}</dd>
        ${d.imported && (d.imported.users || d.imported.nodes || d.imported.cf_accounts) ? `<dt>Imported</dt><dd>from config.yaml on ${esc(fmt.time(d.imported.at))}</dd>` : ""}</dl></div></div>`;
    this.saveForm($("#genForm"), () => this.general());
  },
  saveForm(form, after) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      $$("input[type=checkbox]", e.target).forEach((c) => (fd[c.name] = c.checked));
      try { await api("/api/admin/general", { method: "PUT", body: fd }); toast("Saved", "ok"); after(); }
      catch (err) { toast(err.message, "bad"); }
    });
  },

  async signin() {
    const [d, us] = await Promise.all([api("/api/admin/general"), api("/api/admin/users")]);
    if (S.page !== "settings") return;
    const g = d.settings;
    const on = us.items.filter((x) => x.totp_on).length;
    const req = g.twofa_required || "nobody";
    const missing = us.items.filter((x) => !x.totp_on && !x.disabled && (req === "everyone" || (req === "superadmin" && x.role === "superadmin")));
    $("#setBody").innerHTML = `
      <form class="panel" id="signForm"><div class="hd"><h2>Sign-in security</h2></div><div class="bd form" style="max-width:680px">
        <div class="fl">Require two-step sign-in for
          <span class="segs" data-req>${[["nobody", "Nobody"], ["superadmin", "Superadmins"], ["everyone", "Everyone"]].map(([v, l]) => `<button type="button" data-v="${v}" class="${req === v ? "on" : ""}">${l}</button>`).join("")}</span>
          <input type="hidden" name="twofa_required" value="${esc(req)}">
          <div class="hint">People it applies to set it up right after their next sign-in, with an authenticator app on their phone.
            ${fmt.plural(on, "user")} of ${us.items.length} ${on === 1 ? "has" : "have"} it on${missing.length ? ` · not yet: ${missing.map((x) => esc(x.username)).join(", ")}` : ""}.
            Lost phone? Reset it under <a href="#/settings/users">Users</a>, or on the server: <code>gwconsole reset-2fa &lt;user&gt;</code></div></div>
        <label>Allow sign-in only from these networks<input name="allowed_networks" type="text" value="${esc(g.allowed_networks)}" placeholder="anywhere — e.g. 192.168.10.0/24, 100.64.0.0/10">
          <div class="hint">Comma-separated addresses or networks. Empty = anywhere. Your current address must be in the list. Locked out? On the server: <code>gwconsole allow-all</code></div></label>
        <label class="check"><input type="checkbox" name="signin_alerts" ${g.signin_alerts ? "checked" : ""}> Message me (Telegram/Discord) on a sign-in from a new address, and when an address is locked out after failed attempts</label>
        <div class="two"><label>Sign-in lasts (hours)<input name="session_hours" type="text" value="${g.session_hours}"><div class="hint">The longest a sign-in can last, whatever anyone does.</div></label>
          <label>Longest time away before sign-out<select name="max_idle_minutes">${[[0, "No limit — each user chooses"], [15, "15 min"], [30, "30 min"], [60, "1 h"], [240, "4 h"], [480, "8 h"]].map(([v, l]) => `<option value="${v}" ${+g.max_idle_minutes === v ? "selected" : ""}>${l}</option>`).join("")}</select>
            <div class="hint">Caps “Sign me out when I'm away” in everyone's My account, and applies to users who never chose.</div></label></div>
        <div class="row"><button class="btn pri" type="submit">Save</button></div></div></form>
      <div class="panel"><div class="bd small muted">Signed-in browsers are listed under <a href="#/settings/users">Users &amp; sessions</a>, where you can sign any of them out.</div></div>`;
    $("[data-req]").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-v]");
      if (!b) return;
      $$("[data-req] button").forEach((x) => x.classList.toggle("on", x === b));
      $("[name=twofa_required]").value = b.dataset.v;
    });
    this.saveForm($("#signForm"), () => this.signin());
  },

  // ============================================================ MONITORING
  async monitoring() {
    const d = await api("/api/admin/monitor");
    if (S.page !== "settings" || this.tab !== "monitoring") return;
    const m = d.settings;
    const num = (k, l, hint = "") => `<label>${l}<input name="${k}" type="text" value="${esc(m[k])}">${hint ? `<div class="hint">${hint}</div>` : ""}</label>`;
    const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    $("#setBody").innerHTML = `<form class="scol" id="monForm">
      <div class="panel"><div class="hd"><h2>Checks</h2></div><div class="form2">
        ${num("check_every", "Check sites every (seconds)")}${num("health_every", "Read server health every (seconds)")}
        ${num("down_after", "Site is down after (failed checks in a row)")}${num("slow_ms", "Site is slow above (ms)", "Per-site override in the site's details on the Monitoring page")}
      </div></div>
      <div class="panel"><div class="hd"><h2>Alert thresholds</h2><span class="meta">warning / critical</span></div><div class="form2">
        <label>Disk used (%)<span class="pair"><input name="disk_warn" type="text" value="${m.disk_warn}"> / <input name="disk_crit" type="text" value="${m.disk_crit}"></span></label>
        ${num("mem_crit", "Memory used — critical (%)")}
        <label>CPU load above (× cores) for (minutes)<span class="pair"><input name="load_factor" type="text" value="${m.load_factor}"> for <input name="load_minutes" type="text" value="${m.load_minutes}"></span></label>
        <label>Backend 5xx above (%) for (minutes), at least (requests)<span class="pair"><input name="err5xx_pct" type="text" value="${m.err5xx_pct}"> for <input name="err5xx_minutes" type="text" value="${m.err5xx_minutes}"> min <input name="err5xx_min" type="text" value="${m.err5xx_min}"></span></label>
        <label>Certificate expires in (days)<span class="pair"><input name="cert_warn" type="text" value="${m.cert_warn}"> / <input name="cert_crit" type="text" value="${m.cert_crit}"></span></label>
        <label>Watched service stopped<input type="text" value="critical, right away" disabled></label>
      </div></div>
      <div class="grid2">
        <div class="panel"><div class="hd"><h2>History</h2><span class="meta">${d.db_bytes ? `database now ${fmt.bytes(d.db_bytes)}` : ""}</span></div><div class="form2">
          ${num("keep_raw_hours", "Every minute for (hours)")}${num("keep_15m_days", "15-minute averages for (days)")}${num("keep_daily_days", "Daily traffic totals for (days)")}
        </div></div>
        <div class="panel"><div class="hd"><h2>Weekly summary</h2><span class="meta">to your Notifications channels</span></div><div class="form2">
          <label>Day<select name="summary_day">${days.map((x, i) => `<option value="${i}" ${+m.summary_day === i ? "selected" : ""}>${x}</option>`).join("")}</select></label>
          <label>Time<input name="summary_time" type="text" value="${esc(m.summary_time)}"></label>
          <label class="full">Time zone (also used for daily traffic)<input name="summary_tz" type="text" value="${esc(m.summary_tz)}"></label>
          <div class="full opts"><label><input type="checkbox" name="summary_enabled" ${m.summary_enabled ? "checked" : ""}> Send it</label>
            <label><input type="checkbox" name="summary_telegram" ${m.summary_telegram ? "checked" : ""}> Telegram</label>
            <label><input type="checkbox" name="summary_discord" ${m.summary_discord ? "checked" : ""}> Discord</label>
            <button type="button" class="btn xs" data-a="sumtest">Send one now</button></div>
        </div></div>
      </div>
      <div class="panel"><div class="hd"><h2>Don't check these</h2><span class="meta">Sites found automatically that you don't want watched</span></div>
        <div class="bd small">${d.excluded.map((h) => `<span class="svc">${esc(h)} <button type="button" data-a="unexcl" data-host="${esc(h)}" title="Check it again">✕</button></span>`).join("") || `<span class="muted">None. Use “Don't check this site” in a site's details on the Monitoring page.</span>`}</div></div>
      <div class="row"><button class="btn pri" type="submit">Save</button></div></form>`;
    $("#monForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      $$("input[type=checkbox]", e.target).forEach((c) => (fd[c.name] = c.checked));
      try { await api("/api/admin/monitor", { method: "PUT", body: fd }); toast("Saved", "ok"); this.monitoring(); }
      catch (err) { toast(err.message, "bad"); }
    });
  },
  async act_sumtest(ds, btn) {
    busy(btn, true);
    try {
      const r = await api("/api/admin/monitor/summary", { body: {} });
      modal({ title: "Weekly summary sent", body: `<pre class="out">${esc(r.text || "")}</pre><p class="small muted">Sent to the channels ticked above that are switched on under Notifications.</p>`, actions: [{ label: "Close", value: true }] });
    } finally { busy(btn, false); }
  },
  async act_unexcl(ds) {
    await api(`/api/monitor/sites/${encodeURIComponent(ds.host)}`, { method: "PUT", body: { excluded: false } });
    toast(`${ds.host} is checked again`, "ok");
    this.monitoring();
  },

  // ============================================================ CONFIG HISTORY
  async history() {
    const h = await api("/api/admin/config-history?limit=100").catch((e) => ({ items: [], error: e.message }));
    if (S.page !== "settings" || this.tab !== "history") return;
    $("#setBody").innerHTML = `<div class="panel"><div class="hd"><h2>Changes</h2><span class="meta">From the dashboard or made outside it · stored in a local git repository</span></div>
      <div class="bd flush tbl-wrap"><table><thead><tr><th>When</th><th>Who</th><th>What</th><th></th></tr></thead><tbody>
      ${(h.items || []).map((c) => `<tr><td class="small">${esc(fmt.short(c.at))}</td><td>${c.author === "outside the dashboard" ? pill("warn", "outside the dashboard") : esc(c.author)}</td>
        <td class="small">${esc(c.subject)}</td><td><button class="btn sm" data-a="histshow" data-id="${esc(c.id)}">Show</button></td></tr>`).join("") || `<tr><td colspan="4" class="empty">${esc(h.error || "Nothing recorded yet — the first copy is taken at the next check.")}</td></tr>`}
      </tbody></table></div></div>`;
  },

  // ============================================================ ABOUT & UPDATES
  async about() {
    const [d, v] = await Promise.all([api("/api/system"), api("/api/versions").catch((e) => ({ error: e.message, items: [] }))]);
    if (S.page !== "settings" || this.tab !== "about") return;
    renderFooter(d);
    const u = d.update || {}, avail = u.available || [], running = u.state === "running", host = d.host || {};
    const next = avail[0];
    const rel = Object.fromEntries((d.releases || []).map((r) => [r.version, r]));
    const me = rel[d.version] || {};
    const hist = d.history || [];
    const lastUp = hist.find((h) => h.result === "done" && String(h.to || "").replace(/^v/, "") === d.version && h.from);
    const typeName = { patch: "bug-fix release", minor: "feature release", major: "major release", first: "first release" };
    const checked = u.checked_at ? `checked ${fmt.ago(u.checked_at)}${u.checked_by && u.checked_by !== "schedule" ? ` by ${esc(u.checked_by)}` : " (nightly)"}` : "not checked yet";
    const newer = (x) => { const a = String(x || "").replace(/^v/, "").split(".").map(Number), b = d.version.split(".").map(Number); for (let i = 0; i < 3; i++) if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0); return false; };
    // a failed update only matters while this dashboard is still older than the version it tried
    const recentFail = ["rolled_back", "failed"].includes(u.state) && u.finished_at && Date.now() / 1000 - u.finished_at < 7 * 86400 && newer(u.target);
    const opt = (k, label) => `<label><input type="checkbox" data-gs="${k}" ${d.settings?.[k] ? "checked" : ""}> ${label}</label>`;
    const steps = (to) => `<div class="steps">What happens: <span>① Back up settings &amp; database</span><i>→</i><span>② Install ${esc(to)}</span><i>→</i><span>③ Health check</span><i>→</i><span>④ Back to v${esc(d.version)} if it fails</span></div>`;
    let box;
    if (running) {
      box = `<div class="ubox"><div class="st"><div class="ic">⟳</div><div><h3>Updating to ${esc(u.target)}…</h3><div class="sub">${esc(u.message || "installing")}</div></div>
        <div class="r"><button class="btn sm pri" data-a="updwatch">Show progress</button></div></div>${steps(u.target)}</div>`;
    } else if (next) {
      const notes = this.relSections(next.notes);
      box = `<div class="ubox"><div class="st"><div class="ic">↑</div><div><h3>Update available: ${esc(next.version)}</h3>
          <div class="sub">${esc(typeName[this.relType(next.version)])}${next.date ? ` · ${esc(next.date)}` : ""} · ${checked}${avail.length > 1 ? ` · ${avail.length} versions newer than yours` : ""}</div></div>
        <div class="r"><button class="btn sm" data-a="updcheck">Check now</button><button class="btn sm pri" data-a="updinstall" data-v="${esc(next.version)}">Update to ${esc(next.version)}</button></div></div>
        <div class="chg"><b>What's in ${esc(next.version)}</b><ul style="margin:4px 0 0;padding-left:18px;color:var(--muted)">${Object.entries(notes).flatMap(([k, items]) => items.slice(0, 4).map((i) => `<li>${esc(k)}: ${this.inl(i)}</li>`)).slice(0, 6).join("")}</ul>
          <span class="sub">Full notes in Version history below.</span></div>
        ${steps(next.version)}
        <div class="opts">${opt("update_check", "Check every night")}${opt("auto_update_patch", "Install bug-fix releases (x.y.Z) automatically")}${opt("update_notify", "Message me on Telegram/Discord when a new version is out")}</div></div>`;
    } else {
      box = `<div class="ubox ${recentFail ? "bad" : "ok"}"><div class="st"><div class="ic">${recentFail ? "!" : "✓"}</div><div>
          <h3>${recentFail ? esc(u.message || "The last update failed") : u.checked_at ? "You're on the newest version" : "Check for updates"}</h3><div class="sub">${checked}${d.pending ? " · <b>waiting for the helper service…</b>" : ""}</div></div>
        <div class="r">${recentFail ? `<button class="btn sm" data-a="updwatch">Show log</button>` : ""}<button class="btn sm ${u.checked_at ? "" : "pri"}" data-a="updcheck">Check now</button></div></div>
        ${u.error ? `<div class="out bad">${esc(u.error)}</div>` : ""}
        <div class="small muted">An update backs up settings and the database first. If the new version doesn't start, it goes back to this one automatically.</div>
        <div class="opts">${opt("update_check", "Check every night")}${opt("auto_update_patch", "Install bug-fix releases (x.y.Z) automatically")}${opt("update_notify", "Message me on Telegram/Discord when a new version is out")}</div></div>`;
    }
    const sw = (v.items || []).map((x) => `<tr><td><b>${esc(x.node)}</b><div class="sub">${x.kind === "haproxy" ? "HAProxy" : "cloudflared"}</div></td>
        <td class="mono small" title="${esc(x.installed || "")}">${esc(String(x.installed || "–").split(/[-+~]/)[0])}</td>
        <td class="mono small" title="${esc(x.kind === "haproxy" ? x.candidate || "" : x.latest || "")}">${esc(String(x.kind === "haproxy" ? (x.candidate || "–") : (x.latest || "–")).split(/[-+~]/)[0])}${x.latest_error ? ` <span class="muted" title="${esc(x.latest_error)}">?</span>` : ""}</td>
        <td>${x.error ? pill("crit", "unreachable") : x.kind === "cloudflared" && x.update ? `<button class="btn xs pri op" data-a="cfdupdate" data-name="${esc(x.node)}">Update</button>`
          : x.update ? `<span class="sub" title="Update HAProxy through the OS in a maintenance window">${pill("warn", "update available")}</span>` : pill("ok", "up to date")}</td></tr>`).join("");
    const items = [
      ...avail.map((a) => ({ version: a.version.replace(/^v/, ""), date: a.date || "", type: this.relType(a.version), summary: "", sections: this.relSections(a.notes), avail: true })),
      ...(d.releases || []).filter((r) => !avail.some((a) => a.version.replace(/^v/, "") === r.version)),
    ];
    this.relItems = items;
    if (!this.relOpen) this.relOpen = new Set([d.version, ...(next ? [next.version.replace(/^v/, "")] : [])]);
    $("#setBody").innerHTML = `
      <div class="hero2">
        <div class="vcard"><div class="brand2">GW<b>//</b>CONSOLE</div>
          <div class="big">v${esc(d.version)} <small>installed</small></div>
          <dl>${me.date ? `<dt>Released</dt><dd>${esc(this.day(me.date))} · ${esc(typeName[me.type] || "")}</dd>` : ""}
            <dt>Installed here</dt><dd>${lastUp ? `${esc(fmt.time(lastUp.at))} by ${esc(lastUp.by || "?")}` : hist[0] ? esc(fmt.time(hist.find((h) => String(h.to || "").replace(/^v/, "") === d.version)?.at || hist[0].at)) : "–"}</dd>
            <dt>Installed from</dt><dd>${d.source === "tarball" ? "a release tarball (update with install.sh)" : "GitHub (git clone)"}${d.build && d.build !== `v${d.version}` ? ` · ${esc(d.build)}` : ""}</dd>
            <dt>Running for</dt><dd>${host.running != null ? fmt.dur(host.running) : "–"}</dd>
            ${lastUp ? `<dt>Previous version</dt><dd>${esc(String(lastUp.from).replace(/^v?/, "v"))} · kept for rollback</dd>` : ""}
            <dt>Host</dt><dd class="mono small">${esc([host.hostname, host.os, host.python ? "Python " + host.python : ""].filter(Boolean).join(" · "))}</dd></dl></div>
        ${box}
      </div>
      <div class="grid2b">
        <div class="panel"><div class="hd"><h2>Version history</h2><span class="meta">Release notes for every version</span>
          <div class="acts"><span class="segs" id="relF">${[["all", "All"], ["feat", "Features"], ["fix", "Fixes"]].map(([k, l]) => `<button type="button" data-a="relf" data-f="${k}" class="${(this.relFilter || "all") === k ? "on" : ""}">${l}</button>`).join("")}</span></div></div>
          <div class="tl" id="relTl"></div></div>
        <div class="scol">
          <div class="panel"><div class="hd"><h2>Update history</h2><span class="meta">on this dashboard</span></div>
            <div class="bd flush tbl-wrap">${hist.length ? `<table><thead><tr><th>When</th><th>Change</th><th>By</th><th>Result</th><th></th></tr></thead><tbody>
            ${hist.slice(0, 12).map((h, i) => `<tr><td class="small">${esc(fmt.short(h.at))}</td>
              <td class="mono small">${h.kind === "install" ? `install ${esc(h.to)}` : h.kind === "restore" ? `restore ${esc(String(h.name || "").replace(/^gwconsole-|\.tar\.gz$/g, ""))}` : `${esc(String(h.from || "?").replace(/^v/, ""))} → ${esc(String(h.to || "?").replace(/^v/, ""))}`}</td><td>${esc(h.by || "–")}</td>
              <td>${h.result === "done" ? pill("ok", `done${h.seconds ? ` · ${h.seconds} s` : ""}`) : h.result === "rolled_back" ? pill("warn", "rolled back") : pill("crit", h.result)}</td>
              <td>${i === 0 && h.by !== "installer" && hist[0].kind === "upgrade" ? `<button class="btn xs" data-a="updwatch">Log</button>` : ""}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No updates recorded yet.</div>`}</div></div>
          <div class="panel"><div class="hd"><h2>Software on your nodes</h2></div>
            <div class="bd flush tbl-wrap"><table><thead><tr><th>Node</th><th>Installed</th><th>Latest</th><th></th></tr></thead>
            <tbody>${sw || `<tr><td colspan="4" class="empty">${esc(v.error || "No nodes.")}</td></tr>`}</tbody></table></div></div>
        </div>
      </div>`;
    this.drawReleases(d.version);
    $$("[data-gs]").forEach((c) => c.addEventListener("change", async () => {
      try { await api("/api/admin/general", { method: "PUT", body: { [c.dataset.gs]: c.checked } }); toast("Saved", "ok"); } catch (err) { toast(err.message, "bad"); c.checked = !c.checked; }
    }));
  },
  day(iso) { return fmt.date(new Date(iso + "T12:00:00").getTime() / 1000); },
  inl(t) { return esc(t).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>"); },
  relType(v) {
    const [x, y, z] = String(v).replace(/^v/, "").split(".").map(Number);
    return x === 1 && y === 0 && z === 0 ? "first" : z ? "patch" : y === 0 ? "major" : "minor";
  },
  relSections(md) {
    const out = {};
    let sec = null;
    for (const line of String(md || "").split("\n")) {
      const h = line.match(/^### (.+)/);
      if (h) { sec = out[h[1].split("/")[0].trim()] = []; continue; }
      if (!sec) continue;
      if (/^- /.test(line)) sec.push(line.slice(2).trim());
      else if (/^\s+\S/.test(line) && !/^\s+- /.test(line) && sec.length) sec[sec.length - 1] += " " + line.trim();
    }
    return out;
  },
  drawReleases(cur) {
    const f = this.relFilter || "all";
    const tag = { patch: ["patch", "bug fix"], minor: ["minor", "features"], major: ["major", "major"], first: ["first", "first release"] };
    const rows = (this.relItems || []).filter((r) => f === "all" || (f === "fix" ? r.type === "patch" : r.type !== "patch"));
    $("#relTl").innerHTML = rows.map((r) => {
      const open = this.relOpen.has(r.version);
      const c = Object.fromEntries(Object.entries(r.sections).map(([k, v]) => [k.toLowerCase(), v.length]));
      const summary = r.summary || (r.sections.Added || r.sections.Fixed || r.sections.Changed || []).map((i) => (i.match(/^\*\*(.+?)\*\*/) || [, i.split(":")[0].split(". ")[0]])[1]).slice(0, 3).join("; ");
      const cols = ["Added", "Changed", "Fixed"].filter((k) => r.sections[k]?.length);
      return `<div class="tli ${r.version === cur ? "cur" : r.avail ? "new" : ""}"><div class="rail"><i></i></div><div class="body">
        <div class="top2"><span class="ver">v${esc(r.version)}</span><span class="tag2 ${tag[r.type][0]}">${tag[r.type][1]}</span>${r.date ? `<span class="date">${esc(this.day(r.date))}</span>` : ""}
          ${r.version === cur ? pill("ok", "installed") : r.avail ? pill("warn", "available") : ""}
          <span class="cnt">${c.added ? `<span class="cn a">${c.added} added</span>` : ""}${c.changed ? `<span class="cn c">${c.changed} changed</span>` : ""}${c.fixed ? `<span class="cn f">${c.fixed} fixed</span>` : ""}</span></div>
        <div class="ttl ${r.avail ? "muted" : ""}">${this.inl(summary)}</div>
        ${open && cols.length ? `<div class="notes" style="grid-template-columns:repeat(${cols.length},minmax(0,1fr))">${cols.map((k) => `<div><h4>${k}</h4><ul>${r.sections[k].map((i) => `<li>${this.inl(this.head(i))}</li>`).join("")}</ul></div>`).join("")}</div>` : ""}
        <button type="button" class="tog" data-a="reltog" data-v="${esc(r.version)}">${open ? "Hide notes ▴" : "Show notes ▾"}</button>
        ${open && cols.length ? ` <button type="button" class="tog" data-a="relfull" data-v="${esc(r.version)}">· Full notes</button>` : ""}</div></div>`;
    }).join("") || `<div class="empty">No releases match.</div>`;
  },
  /** the short head of a changelog item: its bold title, or its first sentence */
  head(i) {
    const b = i.match(/^\*\*(.+?)\*\*/);
    if (b) return `**${b[1].replace(/[.:]$/, "")}**`;
    const t = i.split(/(?<=\.)\s|:\s/)[0];
    return t.length > 110 ? t.slice(0, 107) + "…" : t;
  },
  act_relfull(ds) {
    const r = (this.relItems || []).find((x) => x.version === ds.v);
    if (!r) return;
    const md = Object.entries(r.sections).map(([k, items]) => `### ${k}\n` + items.map((i) => `- ${i}`).join("\n")).join("\n");
    modal({ title: `What's in v${r.version}`, size: "lg", body: `<div class="md">${mdLite(md)}</div>`, actions: [{ label: "Close", value: true }] });
  },
  act_reltog(ds) {
    this.relOpen.has(ds.v) ? this.relOpen.delete(ds.v) : this.relOpen.add(ds.v);
    this.drawReleases($(".tli.cur .ver")?.textContent.replace(/^v/, ""));
  },
  act_relf(ds) {
    this.relFilter = ds.f;
    $$("#relF button").forEach((b) => b.classList.toggle("on", b.dataset.f === ds.f));
    this.drawReleases($(".tli.cur .ver")?.textContent.replace(/^v/, ""));
  },
  async act_updcheck(ds, btn) {
    busy(btn, true);
    const before = (await api("/api/system")).update?.checked_at || 0;
    await api("/api/system/update/check", { body: {} });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      const d = await api("/api/system");
      if ((d.update?.checked_at || 0) > before) { busy(btn, false); return this.about(); }
      if (i === 10 && d.pending) toast("The helper service isn't picking up requests. On the server: sudo systemctl enable --now gwconsole-helper.path", "bad");
    }
    busy(btn, false);
    this.about();
  },
  async act_updinstall(ds) {
    const d = await api("/api/system");
    const a = (d.update?.available || []).find((x) => x.version === ds.v);
    if (!(await confirmBox(`Update to ${ds.v}?`, `<div class="md" style="max-height:45vh;overflow:auto">${mdLite((a?.notes || "").replace(/^## .*\n?/, ""))}</div>
      <p class="small">The dashboard backs up first, installs, restarts (about a minute; this page reconnects) and checks the new version answers. If it doesn't, it goes back to v${esc(d.version)} automatically.</p>`, `Update to ${ds.v}`))) return;
    await api("/api/system/update/install", { body: { version: ds.v } });
    this.watchUpdate(ds.v);
  },
  act_updwatch() { this.watchUpdate(""); },
  async watchUpdate(target) {
    const body = document.createElement("div");
    body.innerHTML = `<div class="row" data-st>${pill("info", "starting")}</div><pre class="out" data-log style="max-height:50vh;min-height:200px">waiting for the helper…</pre>`;
    let stop = false;
    modal({ title: target ? `Updating to ${target}` : "Update log", body, size: "lg", actions: [{ label: "Close", value: true }] }).then(() => { stop = true; });
    let waited = 0, seenRunning = false;
    while (!stop) {
      await new Promise((r) => setTimeout(r, 2000));
      waited += 2;
      let s;
      try { s = await api("/api/system/update/status"); } catch { $("[data-st]", body).innerHTML = pill("warn", "restarting… reconnecting"); continue; }
      $("[data-log]", body).textContent = s.log || "…";
      $("[data-log]", body).scrollTop = 1e9;
      if (s.state === "running") { seenRunning = true; $("[data-st]", body).innerHTML = pill("info", s.message || "installing…"); }
      if (!seenRunning && s.pending && waited > 20) $("[data-st]", body).innerHTML = pill("crit", "the helper service isn't running — sudo systemctl enable --now gwconsole-helper.path");
      if ((seenRunning || !target) && ["done", "rolled_back", "failed"].includes(s.state)) {
        const ok = s.state === "done";
        $("[data-st]", body).innerHTML = pill(ok ? "ok" : "crit", s.message || s.state) + (ok ? ` <button class="btn sm pri" onclick="location.reload()">Reload the page</button>` : "");
        if (ok && target) setTimeout(() => location.reload(), 4000);
        break;
      }
    }
  },
  async act_cfdupdate(ds, btn) {
    if (!(await confirmBox(`Update cloudflared on ${ds.name}?`, `<p>Installs the newest cloudflared, then restarts this node's tunnels <b>one at a time</b>, waiting for each to come back.
      If one doesn't, cloudflared goes back to the current version and the tunnels are restarted again.</p><p class="small muted">Each tunnel drops its connections for a few seconds while it restarts.</p>`, "Update"))) return;
    busy(btn, true);
    try { const r = await api(`/api/cloudflared/${encodeURIComponent(ds.name)}/update`, { body: {} }); await showOutput(r.ok ? "cloudflared updated" : "cloudflared not updated", r); }
    finally { busy(btn, false); this.about(); }
  },
  async act_histshow(ds) {
    const r = await api(`/api/admin/config-history/${encodeURIComponent(ds.id)}`);
    modal({ title: "Config change", size: "lg", body: renderDiff(r.text), actions: [{ label: "Close", value: true }] });
  },

  // ============================================================ BACKUPS
  async backups() {
    const d = await api("/api/admin/backups");
    if (S.page !== "settings" || this.tab !== "backups") return;
    const st = d.settings, last = d.last;
    $("#setBody").innerHTML = `
      <div class="panel"><div class="hd"><h2>Backups of this dashboard</h2><span class="meta">Settings, keys, users, nodes, accounts, alerts — in /var/backups/gwconsole</span>
        <div class="acts"><button class="btn sm pri" data-a="bknow">Back up now</button></div></div>
        ${last ? `<div class="bd small">${last.ok ? yes(true) : yes(false)} Last backup ${esc(fmt.ago(last.at))}${last.by && last.by !== "schedule" ? ` (by ${esc(last.by)})` : " (nightly)"}${last.ok ? "" : `: <span class="mono">${esc(last.output)}</span>`}
          ${last.ok && /copied to/.test(last.output) ? ` · ${esc(last.output.split("\n").find((l) => /copied to/.test(l)) || "")}` : ""}</div>` : ""}
        ${d.restore && d.restore.state && d.restore.state !== "running" && d.restore.finished_at && Date.now() / 1000 - d.restore.finished_at < 86400
          ? `<div class="bd small">${pill(d.restore.state === "done" ? "ok" : "crit", d.restore.state === "done" ? "restored" : d.restore.state === "rolled_back" ? "rolled back" : "failed")} ${esc(d.restore.message || "")} · ${esc(fmt.ago(d.restore.finished_at))} by ${esc(d.restore.by || "")}</div>` : ""}
        <div class="bd flush tbl-wrap"><table><thead><tr><th>Backup</th><th>Made by</th><th>Kind</th><th>When</th><th class="num">Size</th><th>Check</th><th></th></tr></thead><tbody>
        ${d.items.map((b) => `<tr><td class="mono small">${esc(b.name)}</td><td>${b.version ? `<span class="tag">v${esc(b.version)}</span>` : "–"}</td>
          <td>${{ backup: "nightly / manual", restore: "before a restore" }[b.kind] || "before an update"}</td>
          <td class="small nowrap">${esc(fmt.short(b.at))}</td><td class="num nowrap">${fmt.bytes(b.size)}</td>
          <td class="nowrap">${b.ok ? `<span class="small" style="color:var(--ok)" title="opens, and its database passed an integrity check">✓ verified</span>` : `<span class="small" style="color:var(--crit)" title="${esc(b.error || "")}">✕ damaged</span>`}</td>
          <td><div class="row" style="justify-content:flex-end;flex-wrap:nowrap;gap:6px"><button class="btn sm" data-a="bkdl" data-name="${esc(b.name)}">Download</button>
            ${b.ok ? `<button class="btn sm" data-a="bkrestore" data-name="${esc(b.name)}">Restore…</button>` : ""}</div></td></tr>`).join("") || `<tr><td colspan="7" class="empty">No backups yet.</td></tr>`}
        </tbody></table></div></div>
      <form class="panel" id="bkForm"><div class="hd"><h2>Nightly backup</h2></div><div class="bd form" style="max-width:680px">
        <label class="check"><input type="checkbox" name="nightly_backup" ${st.nightly_backup ? "checked" : ""}> Back up every night (keeps the last 14)</label>
        <div class="two"><label>Also copy it to node<select name="backup_copy_node"><option value="">— don't copy —</option>${d.nodes.map((n) => `<option ${n === st.backup_copy_node ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
          <label>Folder on that node<input name="backup_copy_dir" type="text" value="${esc(st.backup_copy_dir)}"></label></div>
        <div class="hint">A copy on another machine means losing the dashboard host doesn't lose its backups. It uses the dashboard's SSH key; the newest 14 are kept there.</div>
        <div class="row"><button class="btn pri" type="submit">Save</button></div></div></form>
      <div class="panel"><div class="hd"><h2>Restore from a file</h2><span class="meta">a .gwcbak you downloaded, or a .tar.gz from /var/backups/gwconsole of any Gateway Console</span></div>
        <div class="bd"><label class="drop" id="bkDrop"><span class="ic">⤒</span><div><b>Drop a backup file here, or <u>choose a file</u></b>
          <span class="small muted">Up to 200 MB. Encrypted .gwcbak files ask for their passphrase. Nothing changes until you confirm.</span></div>
          <input type="file" id="bkFile" accept=".gwcbak,.gz,.tgz,application/gzip,application/octet-stream" hidden></label>
          <div class="small muted" style="margin-top:10px">Backups contain <code>secret.key</code>, which unlocks the stored Cloudflare tokens and two-step sign-in secrets — keep downloaded copies safe.
            Restoring on the host still works too: <code>gwconsole restore &lt;file&gt;</code></div></div></div>`;
    const drop = $("#bkDrop"), file = $("#bkFile");
    file.addEventListener("change", () => file.files[0] && this.uploadBackup(file.files[0]));
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); const f = e.dataTransfer.files[0]; if (f) this.uploadBackup(f); });
    $("#bkForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      fd.nightly_backup = $("[name=nightly_backup]", e.target).checked;
      try { await api("/api/admin/general", { method: "PUT", body: fd }); toast("Saved", "ok"); this.backups(); } catch (err) { toast(err.message, "bad"); }
    });
  },
  act_sessmore(ds) {
    this.sessOpen = this.sessOpen || {};
    this.sessOpen[ds.name] = !this.sessOpen[ds.name];
    return this.users();
  },
  async act_bknow(ds, btn) {
    busy(btn, true);
    const before = (await api("/api/admin/backups")).last?.at || 0;
    await api("/api/admin/backups/run", { body: {} });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      const d = await api("/api/admin/backups");
      if ((d.last?.at || 0) > before) { busy(btn, false); toast(d.last.ok ? "Backup done" : "Backup failed", d.last.ok ? "ok" : "bad"); return this.backups(); }
      if (i === 10 && d.pending) toast("The helper service isn't picking up requests. On the server: sudo systemctl enable --now gwconsole-helper.path", "bad");
    }
    busy(btn, false);
  },
  // ---- restore: from the list, or from an uploaded file ----
  async act_bkrestore(ds) {
    let p;
    try { p = await api(`/api/admin/backups/${encodeURIComponent(ds.name)}/preview`); } catch (err) { return toast(err.message, "bad"); }
    return this.restoreDialog(p);
  },
  async uploadBackup(f) {
    if (f.size > 200 * 1024 * 1024) return toast("That file is bigger than 200 MB — it isn't a Gateway Console backup", "bad");
    toast(`Uploading ${f.name}…`);
    let up;
    try {
      const r = await fetch("/api/admin/backups/upload", { method: "POST", headers: { "X-GWC": "1", "Content-Type": "application/octet-stream" }, body: f });
      up = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(up.error || `upload failed (${r.status})`);
    } catch (err) { $("#bkFile").value = ""; return toast(err.message, "bad"); }
    $("#bkFile").value = "";
    let pass = "";
    for (;;) {
      if (up.encrypted) {
        const v = await modal({ title: `Passphrase for ${f.name}`, size: "sm", body: `<div class="form"><p class="small" style="margin:0">This backup is encrypted with the passphrase chosen when it was downloaded.</p>
          <label>Passphrase<input type="password" id="bkPass" autocomplete="off"></label></div>`, actions: [{ label: "Cancel", value: false }, { label: "Open", cls: "pri", value: true }],
          onOpen: (bg) => setTimeout(() => $("#bkPass", bg)?.focus(), 50) });
        if (!v) return;
        pass = $("#bkPass")?.value || pass;
      }
      try {
        const p = await api(`/api/admin/backups/upload/${up.upload_id}/open`, { body: { passphrase: pass } });
        return this.restoreDialog(p, f.name);
      } catch (err) {
        toast(err.message, "bad");
        if (!up.encrypted || !/passphrase/.test(err.message)) return;
      }
    }
  },
  async restoreDialog(p, label) {
    const lostBits = [p.lost.users.length ? fmt.plural(p.lost.users.length, "user") + ` (${p.lost.users.slice(0, 4).map(esc).join(", ")})` : "",
      p.lost.nodes.length ? fmt.plural(p.lost.nodes.length, "node") + ` (${p.lost.nodes.slice(0, 4).map(esc).join(", ")})` : "",
      p.lost.activity ? fmt.plural(p.lost.activity, "activity entry", "activity entries") : ""].filter(Boolean);
    const twofa = S.me && S.me.totp_on !== undefined ? S.me.totp_on : true;
    const body = `<div class="bkinfo"><div><div class="l">Made by</div><div class="v">v${esc(p.version || "?")}</div></div><div><div class="l">Taken</div><div class="v">${esc(p.created_ts ? fmt.time(p.created_ts) : p.created || "?")}</div></div>
        <div><div class="l">Users</div><div class="v">${p.users}</div></div><div><div class="l">Nodes</div><div class="v">${p.nodes} · ${fmt.plural(p.cf_accounts, "CF account")}</div></div></div>
      <div class="small muted">Contains: settings and keys (config.yaml, secret.key, SSH key), the database (users, nodes, alerts, history, monitoring), the activity log.</div>
      ${p.newer_than_running ? `<div class="out bad">This backup was made by a newer version than this dashboard. Update first, then restore.</div>` : ""}
      ${!p.db_ok ? `<div class="out bad">The database in this backup is damaged (${esc(p.db_error)}). Pick another backup.</div>` : ""}
      ${p.same_key === false ? `<div class="scopenote">⚠ This backup comes from <b>another dashboard</b> (a different secret.key). That's right when moving to a new host: its stored tokens and two-step secrets come with it.</div>` : ""}
      <div class="warnbox"><b>What happens</b><ul>
        <li>The current state is saved first (a <span class="mono">before-restore</span> backup), so you can undo this.</li>
        <li>The dashboard stops for about 20 seconds, then starts with the backup's settings.</li>
        <li><b>Everyone is signed out.</b> Sign in with the accounts that were in the backup.</li>
        ${lostBits.length ? `<li>Lost (added after the backup): ${lostBits.join(", ")}.</li>` : ""}
        <li>If it doesn't start, the previous state is put back automatically.</li></ul></div>
      <div class="form" style="gap:10px"><div class="two"><label>Your password<input type="password" name="password" autocomplete="current-password"></label>
        <label>Code from your authenticator<input type="text" name="code" inputmode="numeric" placeholder="${twofa ? "6 digits" : "not needed — two-step sign-in is off"}" ${twofa ? "" : "disabled"}></label></div>
        <label><span>Type <b class="mono">RESTORE</b> to confirm</span><input type="text" name="confirm" placeholder="RESTORE" autocomplete="off"></label>
        <div class="ferr" data-err></div></div>`;
    const blocked = p.newer_than_running || !p.db_ok;
    const go = await new Promise((resolve) => {
      let ok = false;
      modal({ title: `Restore ${label || p.name}`, body, actions: [{ label: "Cancel", value: false }, ...(blocked ? [] : [{ label: "Restore and restart", cls: "danger", value: "go" }])],
        onOpen: (bg) => {
          const btn = $(".ft .danger", bg);
          if (!btn) return;
          btn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const v = (n) => $(`[name=${n}]`, bg).value;
            $("[data-err]", bg).textContent = ""; btn.disabled = true;
            try { await api("/api/admin/backups/restore", { body: { name: p.name, password: v("password"), code: v("code"), confirm: v("confirm") } }); ok = true; bg._close(true); }
            catch (err) { $("[data-err]", bg).textContent = err.message; btn.disabled = false; }
          }, true);
        } }).then(() => resolve(ok));
    });
    if (go) this.restoreProgress(p);
  },
  async restoreProgress(p) {
    const w = document.createElement("div");
    w.innerHTML = `<div class="rsteps" data-steps><div class="run">● Asking the root helper to restore ${esc(p.name)}…</div></div>
      <div class="small muted" style="margin-top:8px">If the restored dashboard doesn't answer within 60 s, the saved state is put back automatically.</div>`;
    let close = () => {};
    modal({ title: "Restoring…", size: "sm", body: w, locked: true, onOpen: (bg) => { close = () => bg._close(true); } });
    const steps = $("[data-steps]", w);
    const line = (cls, t) => { steps.insertAdjacentHTML("beforeend", `<div class="${cls}">${esc(t)}</div>`); };
    const started = Date.now();
    let sawDown = false, last = "";
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      let up = false;
      try { up = (await fetch("/api/health")).ok; } catch { up = false; }
      if (!up && !sawDown) { sawDown = true; line("ok", "✓ Current state saved, dashboard stopped — restoring…"); continue; }
      if (!up) continue;
      try {
        const r = await fetch("/api/admin/backups/restore/status", { headers: { "X-GWC": "1" } });
        if (r.status === 401) { close(); return showLogin(`Restored ${p.name}. Sign in with the accounts from that backup.`); }
        const st2 = (await r.json()).restore || {};
        if (st2.name === p.name && st2.state && st2.state !== "running" && (st2.finished_at || 0) * 1000 >= started - 5000) {
          if (st2.state === "done") { close(); return showLogin(`Restored ${p.name}. Sign in with the accounts from that backup.`); }
          close();
          return showOutput(st2.state === "rolled_back" ? "Restore rolled back" : "Restore didn't run", { ok: false, output: `${st2.message}\n\n${st2.log || ""}` });
        }
        if (st2.state === "running" && last !== "run") { last = "run"; line("run", "● Restoring and checking the dashboard answers…"); }
      } catch { /* starting up */ }
      if (i === 12 && !sawDown) line("wait", "Still waiting for the root helper. On the server: sudo systemctl enable --now gwconsole-helper.path");
    }
    close();
    toast("The restore is taking long — check Settings → Backups, or on the server: gwconsole logs", "bad");
  },
  async act_bkdl(ds) {
    await taskModal({ title: "Download backup", submit: "Download", html: `<p style="margin:0">The file is encrypted with a passphrase you choose now. You'll need it to restore.</p>
        <label>Passphrase<input name="p1" type="password" autocomplete="new-password" required></label><label>Repeat<input name="p2" type="password" autocomplete="new-password" required></label>`,
      run: async (fd) => {
        if (fd.p1 !== fd.p2) throw new Error("the passphrases don't match");
        if (fd.p1.length < 8) throw new Error("use at least 8 characters");
        const r = await fetch("/api/admin/backups/download", { method: "POST", headers: { "Content-Type": "application/json", "X-GWC": "1" }, body: JSON.stringify({ name: ds.name, passphrase: fd.p1 }) });
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
        const blob = await r.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob); a.download = ds.name.replace(".tar.gz", ".gwcbak"); a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
        return { ok: true, output: `Saved ${a.download}. Restore it with: gwconsole restore <file>` };
      } });
  },
};

function uaShort(ua) {
  ua = ua || "";
  const b = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : /curl/.test(ua) ? "curl" : "browser";
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${b} on ${os}` : b;
}
