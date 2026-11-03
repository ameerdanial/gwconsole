/* Gateway Console web UI — Settings page (superadmin only): users and sessions, Cloudflare
 * accounts with token permission test, nodes with host-key confirmation and SSH test,
 * Telegram/Discord notifications, and general settings. */
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
  tabs: [["users", "Users"], ["cloudflare", "Cloudflare"], ["nodes", "Nodes"], ["notifications", "Notifications"], ["general", "General"]],
  mount(v, params) {
    this.tab = this.tabs.some((t) => t[0] === params[0]) ? params[0] : "users";
    setHeader("Settings", "Superadmin only");
    v.innerHTML = `<div class="stabs">${this.tabs.map(([k, l]) => `<a href="#/settings/${k}" class="${k === this.tab ? "on" : ""}">${l}</a>`).join("")}</div>
      <div id="setBody"><div class="panel"><div class="empty">Loading…</div></div></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
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
      <div class="panel"><div class="hd"><h2>Users</h2><span class="meta">${u.items.length} user(s)</span>
        <div class="acts"><button class="btn sm pri" data-a="adduser">+ Add user</button></div></div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>
        ${u.items.map((x) => {
          const me = x.id === u.me;
          return `<tr class="${x.disabled ? "dim" : ""}"><td><b>${esc(x.username)}</b>${me ? ` <span class="tag">you</span>` : ""}</td>
            <td>${me ? pill("info", x.role) : `<select class="sm" data-userrole="${x.id}">${u.roles.map((r) => `<option ${r === x.role ? "selected" : ""}>${r}</option>`).join("")}</select>`}</td>
            <td>${x.disabled ? pill("mute", "disabled") : x.must_change ? pill("warn", "must change password") : pill("ok", "active")}</td>
            <td class="small">${x.last_login ? esc(fmt.ago(x.last_login)) : "never"}</td>
            <td><div class="row" style="justify-content:flex-end;flex-wrap:nowrap">${me ? `<button class="btn sm" data-a="mypw">Change my password</button>` : `
              <button class="btn sm" data-a="resetpw" data-id="${x.id}" data-name="${esc(x.username)}">Reset password</button>
              <button class="btn sm" data-a="toggle" data-id="${x.id}" data-v="${x.disabled ? 0 : 1}">${x.disabled ? "Enable" : "Disable"}</button>
              <button class="btn sm danger" data-a="deluser" data-id="${x.id}" data-name="${esc(x.username)}">Delete</button>`}</div></td></tr>`;
        }).join("")}</tbody></table></div>
        <div class="bd small muted">${Object.values(ROLE_INFO).map(esc).join("<br>")}</div></div>
      <div class="panel"><div class="hd"><h2>Signed-in sessions</h2><span class="meta">Revoking signs that browser out immediately.</span></div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>User</th><th>From</th><th>Browser</th><th>Last active</th><th>Expires</th><th></th></tr></thead><tbody>
        ${s.items.map((x) => `<tr><td>${esc(x.username)} <span class="sub">${esc(x.role)}</span></td><td class="mono small">${esc(x.ip || "")}</td>
          <td class="small" title="${esc(x.user_agent || "")}">${esc(uaShort(x.user_agent))}</td><td class="small">${esc(fmt.ago(x.last_seen))}</td>
          <td class="small">${esc(fmt.short(x.expires_at))}</td>
          <td>${x.sid === s.mine ? `<span class="tag">this browser</span>` : `<button class="btn sm" data-a="kick" data-sid="${esc(x.sid)}">Revoke</button>`}</td></tr>`).join("")}
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
        <table class="mini-t"><tr><td>Account</td><td>Cloudflare Tunnel</td><td>Edit</td></tr><tr><td>Zone</td><td>Zone</td><td>Read</td></tr><tr><td>Zone</td><td>DNS</td><td>Edit</td></tr></table>
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
        (${d.imported.users} user(s), ${d.imported.nodes} node(s), ${d.imported.cf_accounts} account(s)). Those entries in config.yaml are ignored now — manage everything here.</div></div>` : ""}
      <div class="panel"><div class="hd"><h2>Nodes</h2><span class="meta">The servers this dashboard manages over SSH.</span>
        <div class="acts"><button class="btn sm pri" data-a="addnode">+ Add node</button></div></div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Address</th><th>SSH user</th><th>Host key</th><th></th></tr></thead><tbody>
        ${d.items.map((n) => `<tr><td><b>${esc(n.name)}</b>${n.site ? ` <span class="tag">${esc(n.site)}</span>` : ""}</td>
          <td>${n.kind === "haproxy" ? "HAProxy" : "cloudflared"}</td><td class="mono small">${esc(n.host)}:${n.port}</td>
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
    return `<div class="two"><label>Type<select name="kind" ${n ? "disabled" : ""}><option value="haproxy" ${k === "haproxy" ? "selected" : ""}>HAProxy</option><option value="cloudflared" ${k === "cloudflared" ? "selected" : ""}>cloudflared</option></select></label>
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
      <form class="panel" id="genForm"><div class="hd"><h2>General</h2></div><div class="bd form" style="max-width:640px">
        <label>Dashboard URL<input name="dashboard_url" type="text" value="${esc(g.dashboard_url)}" placeholder="http://192.168.10.50:8088"><div class="hint">Used for links in Telegram/Discord messages.</div></label>
        <div class="two"><label>Sign-in lasts (hours)<input name="session_hours" type="text" value="${g.session_hours}"></label>
          <label>Check alerts every (seconds)<input name="alert_interval" type="text" value="${g.alert_interval}"></label></div>
        <div class="two"><label>Keep alert history (days)<input name="alert_retention_days" type="text" value="${g.alert_retention_days}"></label>
          <label>Config backups kept per file<input name="keep_backups" type="text" value="${g.keep_backups}"></label></div>
        <div class="row"><button class="btn pri" type="submit">Save</button><span class="grow"></span><a class="btn" href="#/setup">Run the setup wizard again</a></div></div></form>
      <div class="panel"><div class="hd"><h2>About</h2></div><div class="bd"><dl class="kv">
        <dt>Version</dt><dd>v${esc(d.version)}</dd><dt>Database</dt><dd class="mono small">${esc(d.db_path)}</dd>
        <dt>Alert checker</dt><dd>${d.engine.last_run ? `last run ${esc(fmt.ago(d.engine.last_run))}` : "not run yet"}${d.engine.last_error ? ` · <span style="color:var(--crit)">${esc(d.engine.last_error)}</span>` : ""}</dd>
        ${d.imported && (d.imported.users || d.imported.nodes || d.imported.cf_accounts) ? `<dt>Imported</dt><dd>from config.yaml on ${esc(fmt.time(d.imported.at))}</dd>` : ""}</dl></div></div>`;
    $("#genForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = Object.fromEntries(new FormData(e.target).entries());
      try { await api("/api/admin/general", { method: "PUT", body: fd }); toast("Saved", "ok"); this.general(); }
      catch (err) { toast(err.message, "bad"); }
    });
  },
};

function uaShort(ua) {
  ua = ua || "";
  const b = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : /curl/.test(ua) ? "curl" : "browser";
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${b} on ${os}` : b;
}
