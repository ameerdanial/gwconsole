/* Gateway Console web UI — config editor side panel.
 * Opens from "Edit config" on the HAProxy and Tunnels pages, over the live stats.
 * Editor tab: validate → review diff → apply (backup, reload/restart, health check, rollback).
 * History tab: every backup with who changed what, diff against the current file, restore. */
"use strict";

const Editor = {
  st: null,

  isOpen() { return !!this.st; },
  isDirty() { return !!(this.st && this.st.dirty); },
  url(suffix = "") { return `/api/cfg/${this.st.kind}/${encodeURIComponent(this.st.ref)}${suffix}`; },

  async open(kind, ref) {
    if (this.st) {
      if (this.st.kind === kind && this.st.ref === ref) return;
      if (!this.close()) return;
    }
    this.st = { kind, ref, dirty: false, original: "", hash: null, backups: [], sel: null };
    const ro = !can("operator");
    const node = kind === "tunnel" ? ref.replace(":", " · ") : ref;
    const bg = document.createElement("div");
    bg.className = "drawer-bg";
    const d = document.createElement("aside");
    d.className = "drawer";
    d.innerHTML = `
      <div class="dhd"><div class="grow" style="min-width:0"><div class="tag">${esc(kind === "tunnel" ? "Tunnel" : "HAProxy")} · ${esc(node)}</div>
          <h3 class="mono" data-fpath>loading…</h3></div>
        <span class="dirty hidden" data-dirty>● unsaved changes</span>
        <button class="btn ghost sm" data-close title="Close (Esc)">✕</button></div>
      <div class="tabs"><button class="tb on" data-t="ed">Editor</button><button class="tb" data-t="hist">History</button></div>
      <div class="dbd" data-pane="ed">
        <div class="row"><span class="muted small" data-info></span><span class="grow"></span>
          <button class="btn sm" data-reload title="Re-read from the server">Reload</button>
          ${ro ? `<span class="pill mute">read-only</span>` : `<button class="btn sm" data-validate title="Ctrl+S">Validate</button><button class="btn sm pri" data-apply>Review &amp; apply</button>`}</div>
        <div class="editor"><div class="gut" data-gut>1</div><textarea spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off" ${ro ? "readonly" : ""} data-ta></textarea></div>
        <pre class="out hidden" data-out></pre>
      </div>
      <div class="dbd hidden" data-pane="hist">
        <div class="hlist" data-hlist><div class="muted small">Loading…</div></div>
        <div class="muted small" data-hinfo></div>
        <div class="hdiff" data-hdiff></div>
        <div class="row"><span class="grow"></span><button class="btn sm" data-load disabled>Load into editor</button>
          ${ro ? "" : `<button class="btn sm pri" data-restore disabled>Restore this version</button>`}</div>
      </div>`;
    document.body.append(bg, d);
    this.el = d; this.bg = bg;
    requestAnimationFrame(() => { bg.classList.add("open"); d.classList.add("open"); });
    clearTimeout(S.timer);

    const ta = $("[data-ta]", d), gut = $("[data-gut]", d);
    this._lines = () => { const n = ta.value.split("\n").length; gut.textContent = Array.from({ length: n }, (_, i) => i + 1).join("\n"); };
    this._mark = () => { this.st.dirty = ta.value !== this.st.original; $("[data-dirty]", d).classList.toggle("hidden", !this.st.dirty); };
    ta.addEventListener("input", () => { this._lines(); this._mark(); });
    ta.addEventListener("scroll", () => { gut.scrollTop = ta.scrollTop; });
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Tab" && !ro) { e.preventDefault(); document.execCommand("insertText", false, "    "); }
      if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); if (!ro) this.validate(); }
    });
    this._key = (e) => { if (e.key === "Escape" && !$(".modal-bg")) this.close(); };
    document.addEventListener("keydown", this._key);
    bg.addEventListener("click", () => this.close());
    d.addEventListener("click", (e) => {
      const t = e.target.closest("button");
      if (!t) return;
      if (t.dataset.close !== undefined) this.close();
      else if (t.dataset.t) this.tab(t.dataset.t);
      else if (t.dataset.reload !== undefined) { if (!this.st.dirty || confirm("Discard your edits and reload from the server?")) this.read(); }
      else if (t.dataset.validate !== undefined) this.validate();
      else if (t.dataset.apply !== undefined) this.review(ta.value, t);
      else if (t.dataset.b) this.pick(t.dataset.b);
      else if (t.dataset.load !== undefined) this.loadSelected();
      else if (t.dataset.restore !== undefined) this.restoreSelected(t);
    });
    try { await this.read(); } catch (e) { this.out(e.message, false); }
  },

  close(force = false) {
    if (!this.st) return true;
    if (!force && this.st.dirty && !confirm("You have unapplied edits. Close and discard them?")) return false;
    document.removeEventListener("keydown", this._key);
    const d = this.el, bg = this.bg;
    d.classList.remove("open"); bg.classList.remove("open");
    setTimeout(() => { d.remove(); bg.remove(); }, 250);
    this.st = null;
    schedule();
    return true;
  },

  tab(t) {
    $$(".tb", this.el).forEach((b) => b.classList.toggle("on", b.dataset.t === t));
    $$("[data-pane]", this.el).forEach((p) => p.classList.toggle("hidden", p.dataset.pane !== t));
    if (t === "hist") this.history();
  },

  out(text, ok) {
    const o = $("[data-out]", this.el);
    o.classList.remove("hidden", "ok", "bad"); o.classList.add(ok ? "ok" : "bad"); o.textContent = text;
  },

  async read() {
    const r = await api(this.url());
    if (!this.st) return;
    this.st.original = r.content; this.st.hash = r.hash; this.st.path = r.path;
    const ta = $("[data-ta]", this.el);
    ta.value = r.content; this._lines(); this._mark();
    $("[data-fpath]", this.el).textContent = r.path;
    $("[data-info]", this.el).textContent = `loaded ${new Date().toLocaleTimeString()} · sha256 ${r.hash.slice(0, 10)}`;
    $("[data-out]", this.el).classList.add("hidden");
  },

  async validate() {
    const b = $("[data-validate]", this.el); busy(b, true);
    try {
      const r = await api(this.url("/validate"), { body: { content: $("[data-ta]", this.el).value } });
      this.out((r.ok ? "✔ Valid\n\n" : "✘ Invalid\n\n") + r.output, r.ok);
    } catch (e) { this.out(e.message, false); } finally { busy(b, false); }
  },

  async review(content, btn, title) {
    let d;
    try { d = await api(this.url("/diff"), { body: { content } }); } catch (e) { return toast(e.message, "bad"); }
    if (!d.diff) return toast("No changes compared to the file on the server.");
    const stale = d.current_hash !== this.st.hash;
    const isHap = this.st.kind === "haproxy";
    const ok = await modal({
      title: title || `Apply changes · ${this.st.ref}`,
      body: `<div class="row"><span class="pill ok">+${d.added}</span><span class="pill crit">−${d.removed}</span><span class="muted small">
        ${isHap ? "Validate with <code>haproxy -c</code> → backup → write → <code>systemctl reload</code> (graceful)" : "Validate with <code>cloudflared ingress validate</code> → backup → write → <code>systemctl restart</code> (tunnel reconnects in a few seconds)"} → health check → auto-rollback on failure.</span></div>
        ${stale ? `<div class="out bad">The file on the server changed since you loaded it. Apply will be refused — reload and redo your edits.</div>` : ""}
        ${renderDiff(d.diff)}`,
      actions: [{ label: "Cancel", value: false }, { label: "Apply now", cls: isHap ? "pri" : "danger", value: true }],
    });
    if (!ok || !this.st) return;
    busy(btn, true);
    this.tab("ed");
    this.out("Applying…", true);
    try {
      const r = await api(this.url("/apply"), { body: { content, base_hash: this.st.hash } });
      const head = { applied: "✔ Applied", noop: "No changes", validate: "✘ Validation failed — nothing changed",
        rolled_back: "✘ Activation failed — ROLLED BACK to the previous config", conflict: "✘ Conflict",
        backup: "✘ Could not write backup — nothing changed", write: "✘ Write failed" }[r.stage] || r.stage;
      const text = `${head}${r.backup ? `\nBackup of the previous version: ${r.backup}` : ""}\n\n${r.output}`;
      if (r.ok) {
        toast("Config applied", "ok");
        await this.read();
        this.st.backups = null;
        refresh(false);
      } else toast(head, "bad");
      this.out(text, r.ok);
    } catch (e) { this.out(e.message, false); } finally { busy(btn, false); }
  },

  // ---------------------------------------------------------------- history
  async history() {
    const list = $("[data-hlist]", this.el);
    try {
      const b = (await api(this.url("/backups"))).backups;
      if (!this.st) return;
      this.st.backups = b;
      $(".tb[data-t=hist]", this.el).textContent = `History (${b.length})`;
      if (!b.length) {
        list.innerHTML = `<div class="muted small">No backups yet. One is saved automatically every time a change is applied.</div>`;
        return;
      }
      list.innerHTML = b.map((x) => {
        const c = x.change;
        const who = c ? `before ${esc(c.user)}'s ${esc(c.action.startsWith("config") ? "change" : c.action)}${c.added != null ? ` · +${c.added} −${c.removed}` : ""}` : "saved automatically";
        return `<button class="hi ${this.st.sel === x.name ? "on" : ""}" data-b="${esc(x.name)}"><b>${esc(x.stamp ? x.stamp.slice(0, 16) : fmt.short(x.mtime))}</b><span class="sub">${who}</span></button>`;
      }).join("");
      if (!this.st.sel) this.pick(b[0].name);
    } catch (e) { list.innerHTML = `<div class="out bad">${esc(e.message)}</div>`; }
  },

  async pick(name) {
    this.st.sel = name;
    $$(".hi", this.el).forEach((h) => h.classList.toggle("on", h.dataset.b === name));
    const box = $("[data-hdiff]", this.el);
    box.innerHTML = `<div class="muted small">Loading…</div>`;
    try {
      const b = await api(this.url(`/backups/${encodeURIComponent(name)}`));
      this.st.selContent = b.content;
      const d = await api(this.url("/diff"), { body: { content: b.content } });
      const info = (this.st.backups || []).find((x) => x.name === name);
      $("[data-hinfo]", this.el).innerHTML = `<span class="mono">${esc(name)}</span> · ${fmt.bytes(info?.size)} — the diff shows what restoring it would change:
        <span class="pill ok">+${d.added}</span> <span class="pill crit">−${d.removed}</span>`;
      box.innerHTML = d.diff ? renderDiff(d.diff) : `<div class="empty">Identical to the current file.</div>`;
      $("[data-load]", this.el).disabled = false;
      const r = $("[data-restore]", this.el);
      if (r) r.disabled = !d.diff;
    } catch (e) { box.innerHTML = `<div class="out bad">${esc(e.message)}</div>`; }
  },

  loadSelected() {
    if (this.st.dirty && !confirm("Replace your current edits with this version?")) return;
    const ta = $("[data-ta]", this.el);
    ta.value = this.st.selContent; this._lines(); this._mark();
    this.tab("ed");
    this.out(`Loaded ${this.st.sel} into the editor. Review & apply to restore it.`, true);
  },

  async restoreSelected(btn) {
    await this.read();   // restore on top of the latest file
    this.review(this.st.selContent, btn, `Restore ${this.st.sel}`);
  },
};
