/* Gateway Console web UI — My account page (every role): profile, change password, preferences
 * (time and date format, time zone, start page, auto-refresh, sign-out when away) and your own
 * signed-in browsers. Preferences are saved on the server, so they follow you to every browser. */
"use strict";

const IDLE_LABEL = { 0: "Only when the sign-in ends", 15: "15 min", 30: "30 min", 60: "1 h", 240: "4 h", 480: "8 h" };
const PAGE_LABEL = { overview: "Overview", monitoring: "Monitoring", traffic: "Traffic", tunnels: "CF Tunnels", haproxy: "HAProxy", alerts: "Alerts", activity: "Activity" };

PAGES.account = {
  every: 0,
  tabs: [["", "Profile & password", "Your details, password and two-step sign-in"], ["prefs", "Preferences", "Time, dates, start page, auto-refresh and signing out when away"],
    ["sessions", "Signed-in browsers", "Where you are signed in right now"]],
  mount(v, params) {
    this.tab = this.tabs.some((t) => t[0] === (params[0] || "")) ? params[0] || "" : "";
    const cur = this.tabs.find((t) => t[0] === this.tab);
    setHeader("My account", "Your profile, password and preferences");
    v.innerHTML = `<div class="setgrid"><nav class="snav"><div class="g">My account</div>${this.tabs.map(([k, l]) =>
        `<a href="#/account${k ? "/" + k : ""}" class="${k === this.tab ? "on" : ""}" data-at="${k}">${esc(l)}${k === "sessions" ? `<span class="c" id="acSessN"></span>` : ""}</a>`).join("")}</nav>
      <div class="scol"><div class="sph"><h2>${esc(cur[1])}</h2><span class="sub">${esc(cur[2])}</span></div>
      <div id="acBody" class="scol"><div class="panel"><div class="empty">Loading…</div></div></div></div></div>`;
    v.addEventListener("click", (e) => this.onClick(e));
  },
  async load() {
    const [a, s] = await Promise.all([api("/api/account"), api("/api/account/sessions")]);
    if (S.page !== "account") return;
    this.a = a;
    const p = a.prefs, cap = a.policy.max_idle_minutes;
    const seg = (name, opts, cur) => `<span class="segs" data-seg="${name}">${opts.map(([v, l]) => `<button type="button" data-v="${esc(String(v))}" class="${String(v) === String(cur) ? "on" : ""}">${esc(l)}</button>`).join("")}</span>`;
    const ex = new Date(); ex.setHours(14, 5, 0, 0);
    const sample = ex.getTime() / 1000;
    const idleOpts = a.choices.idle_minutes.filter((m) => !cap || (m && m <= cap)).map((m) => [m, IDLE_LABEL[m] || `${m} min`]);
    let zones = [];
    try { zones = Intl.supportedValuesOf("timeZone"); } catch { zones = ["Asia/Kuala_Lumpur", "Asia/Singapore", "UTC"]; }
    const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if ($("#acSessN")) $("#acSessN").textContent = s.items.length;
    const profile = `<div class="panel"><div class="prof"><span class="av lg">${esc(initials(a.user))}</span>
        <div><h3>${esc(a.user)} <span class="rolepill ${esc(a.role)}">${esc(a.role)}</span></h3>
          <div class="sub">${a.ip ? `Signed in from <span class="mono">${esc(a.ip)}</span> · ` : ""}last sign-in ${esc(fmt.ago(a.last_login))}${a.created_at ? ` · member since ${esc(fmt.date(a.created_at))}` : ""}</div>
          <div class="sub">${esc(ROLE_INFO[a.role] || "")}</div></div></div></div>`;
    const password = `<form class="panel" id="acPw" autocomplete="on"><div class="hd"><h2>Password</h2><span class="meta">${a.pw_changed_at ? `changed ${esc(fmt.ago(a.pw_changed_at))}` : ""}</span></div>
            <div class="bd form">
              <input type="text" name="username" value="${esc(a.user)}" autocomplete="username" hidden>
              <label>Current password<input name="current" type="password" autocomplete="current-password"></label>
              <div class="two"><label>New password<input name="new" type="password" autocomplete="new-password"></label>
                <label>Repeat new password<input name="repeat" type="password" autocomplete="new-password"></label></div>
              <div class="meter"><i data-meter></i></div><div class="hint" data-mhint>At least 10 characters, with upper and lower case letters and a digit.</div>
              <label class="check"><input type="checkbox" name="others" checked> Sign out my other browsers</label>
              <div class="row"><button class="btn pri" type="submit">Change password</button><span class="ferr" data-err></span></div></div></form>`;
    const prefs = `<form class="panel" id="acPrefs" style="max-width:760px"><div class="hd"><h2>Preferences</h2><span class="meta">saved for your user, on every browser</span></div>
          <div class="bd form">
            <div class="fl">Time format${seg("time24", [[true, `24-hour · 14:05`], [false, `12-hour · 2:05 PM`]], p.time24)}</div>
            <div class="fl">Dates${seg("date_style", [["text", "4 Nov 2026"], ["dmy", "04/11/2026"], ["iso", "2026-11-04"]], p.date_style)}</div>
            <label>Time zone<input name="tz" type="text" list="tzList" value="${esc(p.tz)}" placeholder="${esc(browserTz)} (this browser)">
              <datalist id="tzList">${zones.map((z) => `<option value="${esc(z)}">`).join("")}</datalist>
              <div class="hint">Times on every page are shown in this zone. Leave empty to use this browser's.</div></label>
            <div class="two"><label>Start page<select name="start_page">${a.choices.start_page.map((k) => `<option value="${k}" ${k === p.start_page ? "selected" : ""}>${PAGE_LABEL[k] || k}</option>`).join("")}</select></label>
              <div class="fl">Refresh pages automatically${seg("auto_refresh", [[true, "On"], [false, "Off"]], p.auto_refresh)}</div></div>
            <div class="fl">Sign me out when I'm away for${seg("idle_minutes", idleOpts, cap && (!p.idle_minutes || p.idle_minutes > cap) ? cap : p.idle_minutes)}
              <div class="hint">You get a one-minute warning with “Stay signed in”. Pages refreshing by themselves don't count as being there.${cap ? ` Your superadmin allows up to ${IDLE_LABEL[cap] || cap + " min"}.` : ""} A sign-in never lasts longer than ${a.policy.session_hours} h.</div></div>
            <div class="row"><button class="btn pri" type="submit">Save preferences</button><span class="sub" data-sample></span></div></div></form>`;
    const sessions = `<div class="panel" id="acSess"><div class="hd"><h2>Signed-in browsers</h2><span class="meta">yours only · signing one out takes effect right away</span>
        ${s.items.length > 1 ? `<div class="acts"><button class="btn sm danger" data-act="others">Sign out all others</button></div>` : ""}</div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>Browser</th><th>From</th><th>Signed in</th><th>Last active</th><th></th></tr></thead><tbody>
        ${s.items.map((x) => `<tr><td>${esc(uaShort(x.user_agent))}</td><td class="mono small">${esc(x.ip || "–")}</td><td class="small nowrap">${esc(fmt.short(x.created_at))}</td>
          <td class="small nowrap">${x.this ? "now" : esc(fmt.ago(x.last_active || x.last_seen))}</td>
          <td>${x.this ? `<span class="tag">this browser</span>` : `<button class="btn xs" data-act="end" data-sid="${esc(x.sid)}">Sign out</button>`}</td></tr>`).join("")}
        </tbody></table></div></div>`;
    $("#acBody").innerHTML = this.tab === "prefs" ? prefs : this.tab === "sessions" ? sessions
      : `${profile}<div class="acgrid">${password}<div class="scol" id="ac2fa">${this.twofaPanel ? this.twofaPanel(a) : ""}</div></div>`;
    if ($("[data-sample]")) $("[data-sample]").textContent = `Example: ${fmt.time(sample)}`;
    this.wire();
  },
  wire() {
    const pw = $("#acPw");
    if (pw) this.wirePw(pw);
    const pf = $("#acPrefs");
    if (pf) this.wirePrefs(pf);
  },
  wirePw(pw) {
    pw.new.addEventListener("input", () => {
      const v = pw.new.value;
      const score = (v.length >= 10) + /[a-z]/.test(v) + /[A-Z]/.test(v) + /\d/.test(v) + (v.length >= 14 || /[^A-Za-z0-9]/.test(v));
      const m = $("[data-meter]", pw);
      m.style.width = `${score * 20}%`;
      m.style.background = score >= 5 ? "var(--ok)" : score >= 4 ? "var(--warn)" : "var(--crit)";
      $("[data-mhint]", pw).textContent = !v ? "At least 10 characters, with upper and lower case letters and a digit."
        : score >= 5 ? "Strong" : score === 4 && v.length >= 10 ? "OK — longer is stronger" : "Too weak: at least 10 characters, with upper and lower case letters and a digit.";
    });
    pw.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = $("[data-err]", pw);
      err.textContent = "";
      if (pw.new.value !== pw.repeat.value) { err.textContent = "the new passwords don't match"; return; }
      try {
        await api("/api/account/password", { body: { current: pw.current.value, new: pw.new.value, sign_out_others: pw.others.checked } });
        toast(pw.others.checked ? "Password changed — your other browsers were signed out" : "Password changed", "ok");
        this.load();
      } catch (ex) { err.textContent = ex.message; }
    });
  },
  wirePrefs(pf) {
    pf.addEventListener("click", (e) => {
      const b = e.target.closest("[data-seg] button");
      if (!b) return;
      $$("button", b.parentElement).forEach((x) => x.classList.toggle("on", x === b));
    });
    pf.addEventListener("submit", async (e) => {
      e.preventDefault();
      const body = { tz: pf.tz.value.trim(), start_page: pf.start_page.value };
      $$("[data-seg]", pf).forEach((g) => {
        const v = $("button.on", g)?.dataset.v;
        body[g.dataset.seg] = g.dataset.seg === "idle_minutes" ? +v : g.dataset.seg === "date_style" ? v : v === "true";
      });
      try {
        const r = await api("/api/account/prefs", { method: "PUT", body });
        S.prefs = r.prefs;
        S.me = { ...S.me, prefs: r.prefs, idle_limit: r.idle_limit };
        renderUser(S.me);
        Idle.start(r.idle_limit);
        $("#auto").checked = r.prefs.auto_refresh;
        schedule();
        toast("Preferences saved", "ok");
        this.load();
      } catch (ex) { toast(ex.message, "bad"); }
    });
  },
  twofaPanel(a) {
    const t = a.twofa || {};
    if (!t.on) {
      return `<div class="panel"><div class="hd"><h2>Two-step sign-in</h2>${pill(t.required ? "warn" : "mute", t.required ? "required · off" : "off")}</div>
        <div class="bd"><p class="small" style="margin:0 0 10px">After your password, the dashboard also asks for a 6-digit code from an authenticator app on your phone, so a stolen password alone isn't enough.</p>
        <button class="btn pri" data-act="2fa-on">Turn on…</button></div></div>`;
    }
    const low = t.recovery_left <= 3;
    return `<div class="panel"><div class="hd"><h2>Two-step sign-in</h2>${pill("ok", "on")}<span class="meta">since ${esc(fmt.date(t.set_at))}</span></div>
      <div class="bd scol" style="gap:10px">
        <div class="small"><span style="${low ? "color:var(--warn);font-weight:600" : ""}">${fmt.plural(t.recovery_left, "recovery code")} left</span>${low ? " — make new ones soon" : ""}
          · ${fmt.plural(t.trusted_browsers, "remembered browser")}</div>
        <div class="row" style="gap:8px;flex-wrap:wrap"><button class="btn sm" data-act="2fa-rc">New recovery codes…</button>
          ${t.trusted_browsers ? `<button class="btn sm" data-act="2fa-forget">Forget remembered browsers</button>` : ""}
          ${t.required ? `<span class="sub">Required for your role, so it can't be turned off here.</span>` : `<button class="btn sm danger" data-act="2fa-off">Turn off…</button>`}</div></div></div>`;
  },
  reauth(title, submit, cls, run) {
    return taskModal({ title, submit, cls, size: "sm", html: `<p class="small" style="margin:0">Confirm it's you: your password and the current code from your app (or a recovery code).</p>
      <label>Password<input name="password" type="password" autocomplete="current-password"></label>
      <label>Code from your app<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="14" placeholder="6 digits or a recovery code"></label>`,
      run: (fd) => run({ password: fd.password, ...(/^\d{6}$/.test(fd.code.trim()) ? { code: fd.code.trim() } : { recovery: fd.code }) }) });
  },
  async onClick(e) {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    if (b.dataset.act === "2fa-on") { if (await twofaSetup(false)) { toast("Two-step sign-in is on", "ok"); this.load(); } return; }
    if (b.dataset.act === "2fa-forget") {
      try { const r = await api("/api/account/2fa/browsers", { body: {} }); toast(`Forgot ${fmt.plural(r.forgotten, "browser")} — they ask for a code next time`, "ok"); this.load(); }
      catch (err) { toast(err.message, "bad"); }
      return;
    }
    if (b.dataset.act === "2fa-rc") {
      let codes = null;
      await this.reauth("New recovery codes", "Make new codes", "pri", async (body) => {
        codes = (await api("/api/account/2fa/recovery", { body })).recovery_codes;
        return { ok: true, output: "New codes made — the old ones no longer work." };
      });
      if (codes) await showRecoveryCodes(codes, false);
      return this.load();
    }
    if (b.dataset.act === "2fa-off") {
      const changed = await this.reauth("Turn off two-step sign-in", "Turn off", "danger", async (body) => {
        await api("/api/account/2fa/off", { body });
        return { ok: true, output: "Two-step sign-in is off. Your remembered browsers were forgotten." };
      });
      if (changed) this.load();
      return;
    }
    if (b.dataset.act === "end") {
      try { await api(`/api/account/sessions/${encodeURIComponent(b.dataset.sid)}`, { method: "DELETE" }); toast("That browser is signed out", "ok"); this.load(); }
      catch (err) { toast(err.message, "bad"); }
    }
    if (b.dataset.act === "others") {
      if (!(await confirmBox("Sign out all your other browsers?", "<p>Every browser where you're signed in, except this one, has to sign in again.</p>", "Sign them out", "danger"))) return;
      try { const r = await api("/api/account/sessions/others", { body: {} }); toast(`Signed out ${fmt.plural(r.ended, "browser")}`, "ok"); this.load(); }
      catch (err) { toast(err.message, "bad"); }
    }
  },
};
