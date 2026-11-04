/* Gateway Console web UI — My account page (every role): profile, change password, preferences
 * (time and date format, time zone, start page, auto-refresh, sign-out when away) and your own
 * signed-in browsers. Preferences are saved on the server, so they follow you to every browser. */
"use strict";

const IDLE_LABEL = { 0: "Only when the sign-in ends", 15: "15 min", 30: "30 min", 60: "1 h", 240: "4 h", 480: "8 h" };
const PAGE_LABEL = { overview: "Overview", monitoring: "Monitoring", traffic: "Traffic", tunnels: "CF Tunnels", haproxy: "HAProxy", alerts: "Alerts", activity: "Activity" };

PAGES.account = {
  every: 0,
  mount(v, params) {
    this.focus = params[0] || "";
    setHeader("My account", "Your profile, password and preferences");
    v.innerHTML = `<div id="acBody" class="scol"><div class="panel"><div class="empty">Loading…</div></div></div>`;
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
    $("#acBody").innerHTML = `
      <div class="panel"><div class="prof"><span class="av lg">${esc(initials(a.user))}</span>
        <div><h3>${esc(a.user)} <span class="rolepill ${esc(a.role)}">${esc(a.role)}</span></h3>
          <div class="sub">${a.ip ? `Signed in from <span class="mono">${esc(a.ip)}</span> · ` : ""}last sign-in ${esc(fmt.ago(a.last_login))}${a.created_at ? ` · member since ${esc(fmt.date(a.created_at))}` : ""}</div>
          <div class="sub">${esc(ROLE_INFO[a.role] || "")}</div></div></div></div>
      <div class="acgrid">
        <div class="scol">
          <form class="panel" id="acPw" autocomplete="on"><div class="hd"><h2>Password</h2><span class="meta">${a.pw_changed_at ? `changed ${esc(fmt.ago(a.pw_changed_at))}` : ""}</span></div>
            <div class="bd form">
              <input type="text" name="username" value="${esc(a.user)}" autocomplete="username" hidden>
              <label>Current password<input name="current" type="password" autocomplete="current-password"></label>
              <div class="two"><label>New password<input name="new" type="password" autocomplete="new-password"></label>
                <label>Repeat new password<input name="repeat" type="password" autocomplete="new-password"></label></div>
              <div class="meter"><i data-meter></i></div><div class="hint" data-mhint>At least 10 characters, with upper and lower case letters and a digit.</div>
              <label class="check"><input type="checkbox" name="others" checked> Sign out my other browsers</label>
              <div class="row"><button class="btn pri" type="submit">Change password</button><span class="ferr" data-err></span></div></div></form>
          <div class="soon"><span class="tag3">v1.5</span><div><b>Two-step sign-in</b> (authenticator app) and <b>linking your Telegram</b> will appear here.</div></div>
        </div>
        <form class="panel" id="acPrefs"><div class="hd"><h2>Preferences</h2><span class="meta">saved for your user, on every browser</span></div>
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
            <div class="row"><button class="btn pri" type="submit">Save preferences</button><span class="sub" data-sample></span></div></div></form>
      </div>
      <div class="panel" id="acSess"><div class="hd"><h2>Signed-in browsers</h2><span class="meta">yours only · signing one out takes effect right away</span>
        ${s.items.length > 1 ? `<div class="acts"><button class="btn sm danger" data-act="others">Sign out all others</button></div>` : ""}</div>
        <div class="bd flush tbl-wrap"><table><thead><tr><th>Browser</th><th>From</th><th>Signed in</th><th>Last active</th><th></th></tr></thead><tbody>
        ${s.items.map((x) => `<tr><td>${esc(uaShort(x.user_agent))}</td><td class="mono small">${esc(x.ip || "–")}</td><td class="small">${esc(fmt.short(x.created_at))}</td>
          <td class="small">${x.this ? "now" : esc(fmt.ago(x.last_active || x.last_seen))}</td>
          <td>${x.this ? `<span class="tag">this browser</span>` : `<button class="btn xs" data-act="end" data-sid="${esc(x.sid)}">Sign out</button>`}</td></tr>`).join("")}
        </tbody></table></div></div>`;
    $("[data-sample]").textContent = `Example: ${fmt.time(sample)}`;
    this.wire();
    if (this.focus) { const el = this.focus === "prefs" ? $("#acPrefs") : this.focus === "sessions" ? $("#acSess") : null; el?.scrollIntoView({ block: "start" }); this.focus = ""; }
  },
  wire() {
    const pw = $("#acPw");
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
    const pf = $("#acPrefs");
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
  async onClick(e) {
    const b = e.target.closest("[data-act]");
    if (!b) return;
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
