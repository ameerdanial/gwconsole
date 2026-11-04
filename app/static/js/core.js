/* Gateway Console web UI — core: helpers, API client, modals, roles, login, router.
 * Loaded first; page modules (overview.js, haproxy.js, …) register themselves in PAGES
 * and app.js starts the app. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------------------------------------------------------------- api
class AuthError extends Error {}
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-GWC": "1", "X-GWC-Idle": String(Idle.since()) }, credentials: "same-origin" };
  if (opts.body !== undefined) { init.method = opts.method || "POST"; init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  const r = await fetch(path, init);
  let j = null;
  try { j = await r.json(); } catch { /* non-json */ }
  if (r.status === 401 && path !== "/api/login") { showLogin(j && j.idle ? `You were ${j.error}. Sign in again.` : ""); throw new AuthError("not logged in"); }
  if (r.status === 403 && j && j.must_change) { forcePasswordChange(); throw new AuthError("password change required"); }
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
  // dates and times follow the signed-in user's preferences (My account → Preferences)
  _parts(d) {
    const p = S.prefs || {};
    const o = { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" };
    if (p.tz) o.timeZone = p.tz;
    let parts;
    try { parts = new Intl.DateTimeFormat("en-GB", o).formatToParts(d); } catch { delete o.timeZone; parts = new Intl.DateTimeFormat("en-GB", o).formatToParts(d); }
    const g = Object.fromEntries(parts.map((x) => [x.type, x.value]));
    return { y: +g.year, mo: +g.month, d: +g.day, h: +g.hour % 24, mi: g.minute, s: g.second };
  },
  _M: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
  clock(ts, secs = false) {
    if (!ts) return "–";
    const x = fmt._parts(new Date(typeof ts === "number" ? ts * 1000 : ts));
    const t24 = (S.prefs || {}).time24 !== false;
    const sec = secs ? `:${x.s}` : "";
    if (t24) return `${String(x.h).padStart(2, "0")}:${x.mi}${sec}`;
    return `${x.h % 12 || 12}:${x.mi}${sec} ${x.h < 12 ? "AM" : "PM"}`;
  },
  date(ts, opts = {}) {
    if (!ts) return "–";
    const x = fmt._parts(new Date(typeof ts === "number" ? ts * 1000 : ts));
    const st = (S.prefs || {}).date_style || "text";
    const yr = opts.year !== false;
    const p2 = (n) => String(n).padStart(2, "0");
    if (st === "iso") return yr ? `${x.y}-${p2(x.mo)}-${p2(x.d)}` : `${p2(x.mo)}-${p2(x.d)}`;
    if (st === "dmy") return yr ? `${p2(x.d)}/${p2(x.mo)}/${x.y}` : `${p2(x.d)}/${p2(x.mo)}`;
    return yr ? `${x.d} ${fmt._M[x.mo - 1]} ${x.y}` : `${x.d} ${fmt._M[x.mo - 1]}`;
  },
  time: (ts) => (ts ? `${fmt.date(ts)}, ${fmt.clock(ts)}` : "–"),
  short(ts) {
    if (!ts) return "–";
    const same = fmt._parts(new Date(typeof ts === "number" ? ts * 1000 : ts)).y === fmt._parts(new Date()).y;
    return `${fmt.date(ts, { year: !same })}, ${fmt.clock(ts)}`;
  },
  /** "Today" / "Yesterday" / "Mon 3 Nov 2026" heading for a day */
  day(ts) {
    const k = (t) => fmt.date(t, {});
    const now = Date.now() / 1000;
    if (k(ts) === k(now)) return "Today";
    if (k(ts) === k(now - 86400)) return "Yesterday";
    const wd = new Intl.DateTimeFormat("en-GB", { weekday: "short", ...(S.prefs?.tz ? { timeZone: S.prefs.tz } : {}) }).format(new Date(ts * 1000));
    return `${wd} ${fmt.date(ts)}`;
  },
  /** "1 user" / "2 users" */
  plural: (n, one, many) => `${fmt.n(n)} ${n === 1 ? one : (many || one + "s")}`,
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

function modal({ title, body, actions = [], size = "", onOpen, locked = false }) {
  return new Promise((resolve) => {
    const bg = document.createElement("div");
    bg.className = "modal-bg";
    bg.innerHTML = `<div class="modal ${size}"><div class="hd"><h3>${esc(title)}</h3><div class="grow"></div>
      ${locked ? "" : `<button class="btn ghost sm" data-x>✕</button>`}</div><div class="bd"></div>
      ${actions.length ? `<div class="ft">${actions.map((a, i) => `<button class="btn ${a.cls || ""}" data-i="${i}">${esc(a.label)}</button>`).join("")}</div>` : ""}</div>`;
    const bd = $(".bd", bg);
    if (typeof body === "string") bd.innerHTML = body; else if (body) bd.appendChild(body);
    const close = (v) => { bg.remove(); document.removeEventListener("keydown", onKey); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape" && !locked) close(null); };
    document.addEventListener("keydown", onKey);
    bg.addEventListener("click", (e) => {
      if (!locked && (e.target === bg || e.target.closest("[data-x]"))) return close(null);
      const b = e.target.closest("[data-i]");
      if (b) close(actions[+b.dataset.i].value);
    });
    document.body.appendChild(bg);
    bg._body = bd; bg._close = close;
    if (onOpen) onOpen(bg);
  });
}
/** A small ⋯ menu under `anchor`: items [{label, act, cls, op}] or "-" for a divider. Resolves the picked act. */
function popMenu(anchor, items) {
  $$(".menu").forEach((m) => m.remove());
  return new Promise((resolve) => {
    const m = document.createElement("div");
    m.className = "menu";
    m.innerHTML = items.map((i, k) => i === "-" ? "<hr>" : i.op && !can("operator") ? ""
      : `<button type="button" data-k="${k}" class="${i.cls || ""}">${esc(i.label)}</button>`).join("");
    const wrap = anchor.closest(".kebab") || anchor.parentElement;
    wrap.appendChild(m);
    const off = (e) => { if (!m.contains(e.target)) { done(null); } };
    const done = (v) => { m.remove(); document.removeEventListener("mousedown", off, true); resolve(v); };
    m.addEventListener("click", (e) => { const b = e.target.closest("[data-k]"); if (b) done(items[+b.dataset.k].act); });
    setTimeout(() => document.addEventListener("mousedown", off, true), 0);
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
function taskModal({ title, html, submit, cls = "pri", run, size = "sm", locked = false, onOpen }) {
  const f = document.createElement("form");
  f.className = "form";
  f.innerHTML = `${html}<div class="ferr" data-err></div><pre class="out hidden" data-res></pre>
    <div class="row" style="justify-content:flex-end">${locked ? "" : `<button type="button" class="btn" data-cancel>Cancel</button>`}<button type="submit" class="btn ${cls}" data-submit>${esc(submit)}</button></div>`;
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
      $("[data-cancel]", f)?.classList.add("hidden");
    } catch (ex) {
      if (ex instanceof AuthError) return;
      err.textContent = ex.message; btn.disabled = false; btn.textContent = submit;
      $$("input,select,textarea", f).forEach((x) => (x.disabled = wasDisabled.includes(x)));
    }
  });
  return modal({ title, body: f, size, locked, onOpen: (bg) => {
    close = () => bg._close(changed);
    if (onOpen) onOpen(f, close);
    setTimeout(() => $("input:not([type=checkbox]),select", f)?.focus(), 30);
  } });
}

function showOutput(title, r) {
  return modal({ title, size: "", body: `<div class="row">${pill(r.ok ? "ok" : "crit", r.ok ? "success" : r.stage || "failed")}</div>
    <pre class="out ${r.ok ? "ok" : "bad"}">${esc(r.output || "(no output)")}</pre>`, actions: [{ label: "Close", value: true }] });
}

// ---------------------------------------------------------------- app state & roles
const S = { user: null, role: "viewer", page: "overview", params: [], timer: null, inv: null, cache: {}, summaryTimer: null, prefs: {}, me: null };
const LEVEL = { viewer: 0, operator: 1, superadmin: 2 };
const can = (role) => (LEVEL[S.role] ?? -1) >= LEVEL[role];

function setHeader(title, sub = "") { $("#title").textContent = title; $("#subtitle").textContent = sub; }
function setPulse(state) { const p = $("#pulse"); p.className = "pulse " + (state || ""); }
function stamp() { $("#updated").textContent = "updated " + fmt.clock(Date.now() / 1000, true); }

function showLogin(msg = "") {
  clearTimeout(S.timer); clearInterval(S.summaryTimer); Idle.stop(); Idle.hideWarn();
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#loginErr").textContent = msg;
  $("#loginErr").classList.toggle("info", !!msg);
  loginFooter();
  $("#loginForm [name=user]").focus();
}

// ---------------------------------------------------------------- signed out when away (idle)
/** Tracks the last click/key/touch (shared between tabs), sends it as X-GWC-Idle so auto-refresh doesn't
 *  count as being there, warns a minute before the user's "sign me out when I'm away" limit and signs out. */
const Idle = {
  last: Date.now(), limit: 0, timer: null, warnEl: null,
  mark() {
    Idle.last = Date.now();
    try { localStorage.setItem("gwc-active", String(Idle.last)); } catch { /* private mode */ }
    if (Idle.warnEl) Idle.hideWarn();
  },
  since() {
    let l = Idle.last;
    try { l = Math.max(l, +localStorage.getItem("gwc-active") || 0); } catch { /* private mode */ }
    return Math.max(0, Math.round((Date.now() - l) / 1000));
  },
  start(minutes) {
    Idle.stop();
    Idle.limit = (minutes || 0) * 60;
    if (Idle.limit) Idle.timer = setInterval(Idle.tick, 5000);
  },
  stop() { clearInterval(Idle.timer); Idle.timer = null; },
  async tick() {
    const left = Idle.limit - Idle.since();
    if (left <= 0) {
      Idle.stop(); Idle.hideWarn();
      await api("/api/logout", { body: {} }).catch(() => {});
      showLogin(`You were signed out after ${fmt.plural(Idle.limit / 60, "minute")} away. Sign in again.`);
    } else if (left <= 60) Idle.showWarn(left);
  },
  showWarn(left) {
    if (!Idle.warnEl) {
      Idle.warnEl = document.createElement("div");
      Idle.warnEl.className = "idlewarn";
      Idle.warnEl.innerHTML = `<div><b>Still there?</b> <span data-l></span></div>
        <button class="btn sm pri" data-stay>Stay signed in</button><button class="btn sm" data-out>Sign out</button>`;
      Idle.warnEl.addEventListener("click", (e) => {
        if (e.target.closest("[data-stay]")) { Idle.mark(); api("/api/me").catch(() => {}); }
        if (e.target.closest("[data-out]")) signOut();
      });
      document.body.appendChild(Idle.warnEl);
    }
    $("[data-l]", Idle.warnEl).textContent = `You'll be signed out in ${left} s because you've been away.`;
  },
  hideWarn() { Idle.warnEl?.remove(); Idle.warnEl = null; },
};
let _moveT = 0;
["mousedown", "keydown", "touchstart", "wheel"].forEach((ev) => window.addEventListener(ev, Idle.mark, { passive: true, capture: true }));
window.addEventListener("mousemove", () => { if (Date.now() - _moveT > 15000) { _moveT = Date.now(); Idle.mark(); } }, { passive: true });

async function signOut() {
  await api("/api/logout", { body: {} }).catch(() => {});
  showLogin();
}

// ---------------------------------------------------------------- user card, menu, footer
function initials(name) {
  const p = String(name || "?").split(/[^A-Za-z0-9]+/).filter(Boolean);
  return ((p[0] || "?")[0] + (p[1] ? p[1][0] : (p[0] || "").slice(1, 2))).toUpperCase();
}
function renderUser(me) {
  $("#uav").textContent = initials(me.user);
  $("#who").textContent = me.user;
  $("#whoRole").textContent = me.role;
  $("#whoRole").className = `rolepill ${me.role}`;
  $("#umName").textContent = me.user;
  $("#umSub").textContent = `${me.role[0].toUpperCase() + me.role.slice(1)}${me.idle_limit ? ` · signed out after ${me.idle_limit} min away` : ""}`;
  $("#umNew").innerHTML = `<i>✦</i>What's new in v${esc(me.version)}`;
}
function toggleUserMenu(open) {
  const m = $("#umenu");
  const on = open ?? m.classList.contains("hidden");
  m.classList.toggle("hidden", !on);
  $("#ucard").classList.toggle("open", on);
}
function footerHtml(version, upd) {
  const year = new Date().getFullYear();
  const status = upd === undefined ? "" : upd ? `<a href="#/settings/about" class="updlink">${esc(upd)} available</a><span class="sep">·</span>`
    : `<span class="ok">✓ up to date</span><span class="sep">·</span>`;
  return `<span class="brand3">GW<b>//</b>CONSOLE</span><span>v${esc(version || "")}</span><span class="sep">·</span>${status}<a href="#" data-notes>Release notes</a>
    <span class="grow"></span><span>© ${year} <a href="https://adproject.fun" target="_blank" rel="noopener">ADProject</a>. All rights reserved.</span>`;
}
function renderFooter(upd) { $("#pfoot").innerHTML = footerHtml(S.me?.version, upd); }
async function showWhatsNew() {
  if (can("superadmin")) { location.hash = "#/settings/about"; return; }
  const d = await api("/api/system");
  modal({ title: `What's new in v${d.version}`, size: "lg", body: `<div class="md">${mdLite((d.whatsnew || "").replace(/^## .*\n?/, "")) || "No notes."}</div>`, actions: [{ label: "Close", value: true }] });
}
async function loginFooter() {
  try {
    const h = await fetch("/api/health").then((r) => r.json());
    $("#loginFoot").innerHTML = `GW//CONSOLE v${esc(h.version)} · © ${new Date().getFullYear()} <a href="https://adproject.fun" target="_blank" rel="noopener">ADProject</a>. All rights reserved.`;
  } catch { /* offline */ }
}

async function boot() {
  let me;
  try {
    me = await api("/api/me");
  } catch (e) { if (!(e instanceof AuthError)) toast(e.message, "bad"); return; }
  S.user = me.user; S.role = me.role; S.me = me; S.prefs = me.prefs || {};
  document.body.dataset.role = me.role;
  renderUser(me);
  renderFooter();
  $("#auto").checked = S.prefs.auto_refresh !== false;
  Idle.mark();
  Idle.start(me.idle_limit);
  $("#navSettings").classList.toggle("hidden", !can("superadmin"));
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  if (me.must_change) { await forcePasswordChange(); return; }
  S.inv = await api("/api/inventory");
  updateBanner(me.updated);
  if (can("superadmin")) api("/api/system").then((d) => {
    const av = (d.update || {}).available || [];
    renderFooter(av.length ? av[0].version : null);
  }).catch(() => {});
  if (!location.hash && S.prefs.start_page && S.prefs.start_page !== "overview") history.replaceState(null, "", `#/${S.prefs.start_page}`);
  // fresh install: walk the superadmin through nodes → Cloudflare → alerts (no extra hashchange)
  if (me.setup && !/^#\/setup/.test(location.hash)) history.replaceState(null, "", "#/setup");
  route();
  updateBadge();
  clearInterval(S.summaryTimer);
  S.summaryTimer = setInterval(updateBadge, 30000);
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
$("#logout").addEventListener("click", (e) => { e.preventDefault(); toggleUserMenu(false); signOut(); });
$("#ubtn").addEventListener("click", (e) => { e.stopPropagation(); toggleUserMenu(); });
$("#umenu").addEventListener("click", (e) => {
  if (e.target.closest("#umNew")) { e.preventDefault(); showWhatsNew(); }
  if (e.target.closest("a")) toggleUserMenu(false);
});
document.addEventListener("click", (e) => { if (!e.target.closest("#ucard")) toggleUserMenu(false); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") toggleUserMenu(false); });
$("#hamb").addEventListener("click", () => $("#side").classList.toggle("open"));
$("#nav").addEventListener("click", (e) => { if (e.target.closest("a")) $("#side").classList.remove("open"); });
$("#pfoot").addEventListener("click", (e) => { if (e.target.closest("[data-notes]")) { e.preventDefault(); showWhatsNew(); } });
$("#refresh").addEventListener("click", () => refresh(true));
$("#auto").addEventListener("change", () => schedule());

// ---------------------------------------------------------------- password
const PW_HINT = `<div class="hint">At least 10 characters, with upper and lower case letters and a digit.</div>`;
function changePassword(forced) {
  return taskModal({
    title: forced ? "Set a new password" : "Change your password", submit: "Change password", locked: forced,
    html: `${forced ? `<p style="margin:0">Your password was set by an administrator. Choose your own before continuing.</p>` : ""}
      <label>Current password<input name="current" type="password" autocomplete="current-password" required></label>
      <label>New password<input name="new" type="password" autocomplete="new-password" required>${PW_HINT}</label>
      <label>Repeat new password<input name="repeat" type="password" autocomplete="new-password" required></label>`,
    run: async (fd) => {
      if (fd.new !== fd.repeat) throw new Error("the new passwords don't match");
      await api("/api/account/password", { body: { current: fd.current, new: fd.new } });
      return { ok: true, output: "Password changed. Other sessions of yours were signed out." };
    },
  });
}
let _forcing = false;
async function forcePasswordChange() {
  if (_forcing) return;
  _forcing = true;
  await changePassword(true);
  _forcing = false;
  boot();
}

// ---------------------------------------------------------------- alert badge
async function updateBadge() {
  try {
    const s = await api("/api/alerts/summary");
    const b = $("#alertCount");
    b.classList.toggle("hidden", !s.unacked);
    b.classList.toggle("warn", !s.crit);
    b.textContent = s.unacked;
    S.cache.summary = s;
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------- router
const PAGES = {};
window.addEventListener("hashchange", () => {
  if (Editor.isDirty() && !window.confirm("You have unapplied config edits. Leave and discard them?")) {
    history.back(); return;
  }
  Editor.close(true);
  route();
});
window.addEventListener("beforeunload", (e) => { if (Editor.isDirty()) { e.preventDefault(); e.returnValue = ""; } });

function route() {
  let parts = (location.hash.replace(/^#\/?/, "") || "overview").split("/").map(decodeURIComponent);
  if (parts[0] === "config") {           // v1.1 links: the editor now opens as a side panel
    const [kind, ref] = [parts[1], parts[2]];
    if (kind && ref) S.cache.openEditor = { kind, ref };
    location.replace(kind === "tunnel" ? "#/tunnels" : `#/haproxy${ref ? "/" + encodeURIComponent(ref) : ""}`);
    return;
  }
  const page = PAGES[parts[0]] && (!PAGES[parts[0]].role || can(PAGES[parts[0]].role)) ? parts[0] : "overview";
  const same = page === S.page && $("#view").dataset.page === page && JSON.stringify(parts.slice(1)) === JSON.stringify(S.params);
  S.page = page; S.params = parts.slice(1);
  $$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.p === page));
  if (!same) {
    const fresh = $("#view").cloneNode(false); // drop old listeners
    $("#view").replaceWith(fresh);
    fresh.dataset.page = page;
    PAGES[page].mount($("#view"), S.params);
  }
  refresh(true).then(() => {
    const o = S.cache.openEditor;
    if (o) { S.cache.openEditor = null; Editor.open(o.kind, o.ref); }
  });
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
  if ($("#auto").checked && p.every && !Editor.isOpen()) S.timer = setTimeout(() => refresh(false), p.every * 1000);
}

// ---------------------------------------------------------------- changelog text and the post-update banner
/** Tiny Markdown subset used by CHANGELOG.md: ### headings, - bullets (with continuation lines), **bold**, `code`. */
function mdLite(text) {
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
  let html = "", inList = false, item = "", sub = false;
  const flush = () => { if (item) { html += `<li${sub ? ` class="sub"` : ""}>${inline(item)}</li>`; item = ""; } };
  for (const raw of String(text || "").split("\n")) {
    const line = raw.replace(/\s+$/, "");
    if (/^#{2,4} /.test(line)) { flush(); if (inList) { html += "</ul>"; inList = false; } html += `<h5>${inline(line.replace(/^#+ /, ""))}</h5>`; }
    else if (/^- /.test(line)) { flush(); if (!inList) { html += "<ul>"; inList = true; } item = line.slice(2); sub = false; }
    else if (/^\s+- /.test(line) && inList) { flush(); item = line.trim().slice(2); sub = true; }
    else if (/^\s+\S/.test(line) && item) item += " " + line.trim();
    else if (line.trim()) { flush(); if (inList) { html += "</ul>"; inList = false; } html += `<p>${inline(line)}</p>`; }
  }
  flush();
  if (inList) html += "</ul>";
  return html;
}

function updateBanner(u) {
  $("#updBanner")?.remove();
  if (!u) return;
  const el = document.createElement("div");
  el.id = "updBanner";
  el.className = "banner";
  el.innerHTML = `<span>✨ Gateway Console was updated to <b>v${esc(u.to)}</b>${u.from && /^\d/.test(u.from) ? ` (from v${esc(u.from)})` : ""}.</span>
    <button class="btn sm pri" data-wn>See what's new</button><button class="btn ghost sm" data-x title="Dismiss">✕</button>`;
  const seen = () => { api("/api/whatsnew/seen", { body: {} }).catch(() => {}); el.remove(); };
  el.querySelector("[data-x]").addEventListener("click", seen);
  el.querySelector("[data-wn]").addEventListener("click", async () => {
    const d = await api("/api/system");
    seen();
    modal({ title: `What's new in v${d.version}`, size: "lg", body: `<div class="md">${mdLite((d.whatsnew || "").replace(/^## .*\n?/, ""))}</div>`, actions: [{ label: "Close", value: true }] });
  });
  $(".main").prepend(el);
}
