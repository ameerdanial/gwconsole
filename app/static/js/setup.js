/* Gateway Console web UI — first-run setup wizard (superadmin): Nodes → Cloudflare → Alerts → Done.
 * Shown automatically after a fresh install until finished or skipped; reopen from Settings → General.
 * Every step reuses the Settings forms, so what you set here is exactly what Settings shows. */
"use strict";

PAGES.setup = {
  role: "superadmin",
  steps: [["nodes", "Nodes"], ["cloudflare", "Cloudflare"], ["alerts", "Alerts"], ["done", "Done"]],
  mount(v, params) {
    this.step = this.steps.some((s) => s[0] === params[0]) ? params[0] : "nodes";
    setHeader("Setup", "Three short steps — skip any of them, everything can be changed later in Settings");
    const idx = this.steps.findIndex((s) => s[0] === this.step);
    v.innerHTML = `<div class="wizard">
        <ol class="wsteps">${this.steps.map(([k, l], i) => `<li class="${i < idx ? "past" : i === idx ? "on" : ""}"><a href="#/setup/${k}"><span class="n">${i < idx ? "✓" : i + 1}</span>${l}</a></li>`).join("")}</ol>
        <div id="wizBody"><div class="panel"><div class="empty">Loading…</div></div></div>
        <div class="row wnav">${idx > 0 ? `<a class="btn" href="#/setup/${this.steps[idx - 1][0]}">← Back</a>` : ""}<span class="grow"></span>
          ${this.step !== "done" ? `<button class="btn ghost" data-a="skipall">Skip setup</button><a class="btn pri" href="#/setup/${this.steps[idx + 1][0]}" data-next>Next →</a>` : ""}</div>
      </div>`;
    v.addEventListener("click", (e) => this.onClick(e));
  },
  async load() {
    const d = await api("/api/admin/setup");
    if (S.page !== "setup") return;
    this.d = d;
    PAGES.settings.cache = { nodes: d.nodes, pubkey: d.pubkey, cf: d.cf_accounts };
    const body = $("#wizBody");
    if (this.step === "nodes") body.innerHTML = this.nodesHtml(d);
    if (this.step === "cloudflare") body.innerHTML = this.cfHtml(d);
    if (this.step === "alerts") {
      body.innerHTML = `<div class="panel"><div class="bd small">Get a message on your phone when a backend, a tunnel or a node goes down — and when it recovers.
        Fill in one, both or neither. <span class="muted">Tick "Send alerts", fill it in, Save, then Send test.</span></div></div><div id="wizNotify"></div>`;
      await PAGES.settings.notifications($("#wizNotify"));
    }
    if (this.step === "done") body.innerHTML = this.doneHtml(d);
    const next = $("[data-next]");
    if (next) next.textContent = this.isEmpty(d) ? "Skip this step →" : "Next →";
  },
  isEmpty(d) {
    return { nodes: !d.nodes.length, cloudflare: !d.cf_accounts.length, alerts: !d.notify.telegram && !d.notify.discord }[this.step] ?? false;
  },

  nodesHtml(d) {
    return `<div class="panel"><div class="hd"><h2>Your servers</h2><span class="meta">The hosts running HAProxy and cloudflared — VMs, LXCs or bare metal.</span>
        <div class="acts"><button class="btn sm pri" data-a="addnode">+ Add node</button></div></div>
        <div class="bd">${d.nodes.length ? `<ul class="checks">${d.nodes.map((n) => `<li>${yes(true)}<b>${esc(n.name)}</b>
            <span class="sub">${n.kind === "haproxy" ? "HAProxy" : "cloudflared"} · ${esc(n.user)}@${esc(n.host)}:${n.port}</span>
            <button class="btn sm" data-a="testnode" data-name="${esc(n.name)}">Test</button></li>
            <li class="hidden wtest" data-testrow="${esc(n.name)}"></li>`).join("")}</ul>`
          : `<div class="empty">No nodes yet. Add your HAProxy server first, then the cloudflared one (they can be the same host — add it twice, once per type).</div>`}</div></div>
      <div class="panel"><div class="bd small help">
        <p><b>What you'll need:</b> the node's IP, and either its root password (or a sudo user's) <i>once</i>, or a terminal on it to paste one command.</p>
        <p>The dashboard pins the node's SSH host key — compare the fingerprint it shows with <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on the node.</p></div></div>`;
  },
  cfHtml(d) {
    return `<div class="panel"><div class="hd"><h2>Cloudflare account</h2><span class="meta">Optional: tunnel health from Cloudflare's side, creating tunnels and DNS for hostnames.</span>
        <div class="acts"><button class="btn sm pri" data-a="addcf">+ Add account</button></div></div>
        <div class="bd">${d.cf_accounts.length ? `<ul class="checks">${d.cf_accounts.map((a) => `<li>${yes(a.has_token)}<b>${esc(a.name)}</b><span class="sub mono">${esc(a.account_id)}</span>
            <button class="btn sm" data-a="testcf" data-name="${esc(a.name)}">Test token</button></li><li class="cfres" data-res="${esc(a.name)}"></li>`).join("")}</ul>`
          : `<div class="empty">No account yet. Without one you still get everything on the nodes; Cloudflare-side health and DNS stay off.</div>`}</div></div>
      <div class="panel"><div class="hd"><h2>Where to find these</h2></div><div class="bd small help">
        <p><b>Account ID</b>: <code>dash.cloudflare.com</code> → click a domain → right-hand column, <b>API</b> box → <b>Account ID</b> (also the long code in the address bar).</p>
        <p><b>API token</b>: person icon → <b>Profile</b> → <b>API Tokens</b> → <b>Create Token</b> → <b>Create Custom Token</b>:</p>
        <table class="mini-t"><tr><td>Account</td><td>Cloudflare Tunnel</td><td>Edit</td></tr><tr><td>Zone</td><td>Zone</td><td>Read</td></tr><tr><td>Zone</td><td>DNS</td><td>Edit</td></tr><tr><td>Zone</td><td>Analytics</td><td>Read</td></tr></table>
        <p>Account Resources: your account · Zone Resources: All zones. <b>Test before saving</b> in the form checks it without changing anything.</p></div></div>`;
  },
  doneHtml(d) {
    const row = (ok, t, sub, href) => `<li>${yes(ok)}<b>${t}</b><span class="sub">${sub}</span>${ok ? "" : `<a class="btn sm" href="${href}">Set up</a>`}</li>`;
    const hp = d.nodes.filter((n) => n.kind === "haproxy").length, cf = d.nodes.filter((n) => n.kind === "cloudflared").length;
    const notif = [d.notify.telegram && "Telegram", d.notify.discord && "Discord"].filter(Boolean);
    const url = d.dashboard_url || location.origin;
    return `<div class="panel"><div class="hd"><h2>Ready</h2></div><div class="bd"><ul class="checks">
        ${row(hp > 0, "HAProxy", hp ? `${hp} node(s)` : "no HAProxy node", "#/setup/nodes")}
        ${row(cf > 0, "cloudflared", cf ? `${cf} node(s)` : "no cloudflared node", "#/setup/nodes")}
        ${row(d.cf_accounts.length > 0, "Cloudflare", d.cf_accounts.length ? d.cf_accounts.map((a) => esc(a.name)).join(", ") : "not connected (optional)", "#/setup/cloudflare")}
        ${row(notif.length > 0, "Alerts to your phone", notif.length ? notif.join(" + ") : "off — alerts still show on the Alerts page", "#/setup/alerts")}
        </ul>
        <form class="form" id="wizFinish" style="margin-top:14px;max-width:560px">
          ${d.dashboard_url ? "" : `<label>Dashboard URL <span class="muted">(for links in alert messages)</span><input name="dashboard_url" type="text" value="${esc(url)}"></label>`}
          <div class="row"><button class="btn pri" type="submit">Finish — open the Overview</button></div></form>
        <p class="small muted" style="margin-top:12px">More users (viewer / operator roles): Settings → Users. Reopen this wizard: Settings → General.</p></div></div>`;
  },

  async onClick(e) {
    const b = e.target.closest("[data-a]");
    if (!b) return;
    const a = b.dataset.a;
    try {
      if (a === "skipall") {
        if (!(await confirmBox("Skip setup?", "<p>You can add nodes, Cloudflare and alerts any time under <b>Settings</b>, or reopen this wizard from Settings → General.</p>", "Skip"))) return;
        await api("/api/admin/setup", { body: { done: true } });
        location.hash = "#/overview";
        return;
      }
      const fn = PAGES.settings["act_" + a];
      if (fn) await fn.call(PAGES.settings, b.dataset, b);
    } catch (err) { toast(err.message, "bad"); }
  },
};

document.addEventListener("submit", async (e) => {
  if (e.target.id !== "wizFinish") return;
  e.preventDefault();
  const fd = Object.fromEntries(new FormData(e.target).entries());
  try {
    await api("/api/admin/setup", { body: { done: true, dashboard_url: fd.dashboard_url || "" } });
    S.inv = await api("/api/inventory");
    toast("Setup finished", "ok");
    location.hash = "#/overview";
  } catch (err) { toast(err.message, "bad"); }
});
