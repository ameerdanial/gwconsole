/* Gateway Console web UI — small chart helpers drawn as inline SVG (no libraries, no CDN):
 * line charts with a hover crosshair and tooltip, stacked bar charts, and sparklines.
 * Colours are a dark-theme categorical palette checked for contrast on the panel background. */
"use strict";

const Charts = {
  C: ["#3987e5", "#d95926", "#199e70", "#c98500"],
  OTHER: "#5d627d",
  GRID: "#262b42",
  AXIS: "#5d627d",

  color(i, name) { return name === "other" ? this.OTHER : this.C[i % this.C.length]; },

  niceMax(v) {
    if (!(v > 0)) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v))), m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * p;
  },

  legend(names) {
    return `<div class="legend">${names.map((n, i) => `<span><i style="background:${this.color(i, n)}"></i>${esc(n)}</span>`).join("")}</div>`;
  },

  /** series: [{name, data: [[ts, value], ...]}] (ts in seconds). opts: yFmt, yMax, h, xFmt */
  line(el, series, opts = {}) {
    const w = Math.max(320, el.clientWidth || 640), h = opts.h || 220;
    const pad = { l: 56, r: 12, t: 10, b: 24 }, iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
    const pts = series.flatMap((s) => s.data);
    if (!pts.length) { el.innerHTML = `<div class="empty">No data yet — history builds up as checks run.</div>`; return; }
    // x axis covers the whole selected range (opts.span seconds up to now), not just the data seen so far
    const t1 = opts.span ? Math.max(Date.now() / 1000, ...pts.map((p) => p[0])) : Math.max(...pts.map((p) => p[0]));
    const t0 = opts.span ? t1 - opts.span : Math.min(...pts.map((p) => p[0]));
    const yMax = opts.yMax || this.niceMax(Math.max(opts.minMax || 0, ...pts.map((p) => p[1])) * 1.1);
    const yFmt = opts.yFmt || ((v) => fmt.n(Math.round(v)));
    const xFmt = opts.xFmt || ((t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
    const x = (t) => pad.l + (t1 === t0 ? iw / 2 : ((t - t0) / (t1 - t0)) * iw);
    const y = (v) => pad.t + ih - (Math.min(v, yMax) / yMax) * ih;
    let s = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" style="display:block">`;
    for (let k = 0; k <= 4; k++) {
      const v = (yMax / 4) * k, yy = y(v);
      s += `<line x1="${pad.l}" x2="${w - pad.r}" y1="${yy}" y2="${yy}" stroke="${this.GRID}"/>`;
      s += `<text x="${pad.l - 8}" y="${yy + 4}" fill="${this.AXIS}" font-size="11" text-anchor="end">${esc(yFmt(v))}</text>`;
    }
    for (let k = 0; k <= 4; k++) {
      const t = t0 + ((t1 - t0) / 4) * k;
      s += `<text x="${x(t)}" y="${h - 6}" fill="${this.AXIS}" font-size="11" text-anchor="${k === 0 ? "start" : k === 4 ? "end" : "middle"}">${esc(xFmt(t))}</text>`;
    }
    series.forEach((sr, i) => {
      let d = "", prev = null;
      const gap = (opts.gap || 0);
      for (const [t, v] of sr.data) {
        d += `${prev == null || (gap && t - prev > gap) ? "M" : "L"}${x(t).toFixed(1)},${y(v).toFixed(1)}`;
        prev = t;
      }
      s += `<path d="${d}" fill="none" stroke="${this.color(i, sr.name)}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
    });
    s += `<line class="xh" x1="0" x2="0" y1="${pad.t}" y2="${pad.t + ih}" stroke="#8b90ab" stroke-dasharray="3 3" visibility="hidden"/>`;
    s += `<rect x="${pad.l}" y="${pad.t}" width="${iw}" height="${ih}" fill="transparent" class="hit"/></svg>`;
    el.innerHTML = (series.length > 1 || opts.legend ? this.legend(series.map((x) => x.name)) : "") + `<div class="chartbox">${s}<div class="tip hidden"></div></div>`;
    const box = $(".chartbox", el), svg = $("svg", box), tip = $(".tip", box), xh = $(".xh", svg);
    $(".hit", svg).addEventListener("mousemove", (e) => {
      const r = svg.getBoundingClientRect(), px = ((e.clientX - r.left) / r.width) * w;
      const t = t0 + ((px - pad.l) / iw) * (t1 - t0);
      const rows = series.map((sr, i) => {
        let best = null;
        for (const p of sr.data) if (!best || Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
        return best && { i, name: sr.name, t: best[0], v: best[1] };
      }).filter(Boolean);
      if (!rows.length) return;
      const tt = rows[0].t;
      xh.setAttribute("x1", x(tt)); xh.setAttribute("x2", x(tt)); xh.setAttribute("visibility", "visible");
      tip.innerHTML = `<div class="tt">${esc(new Date(tt * 1000).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" }))}</div>`
        + rows.sort((a, b) => b.v - a.v).map((r) => `<div class="r"><span><i style="background:${this.color(r.i, r.name)}"></i>${esc(r.name)}</span><b>${esc(yFmt(r.v))}</b></div>`).join("");
      tip.classList.remove("hidden");
      const left = (x(tt) / w) * r.width;
      tip.style.left = left > r.width * 0.6 ? `${left - tip.offsetWidth - 12}px` : `${left + 12}px`;
      tip.style.top = "6px";
    });
    $(".hit", svg).addEventListener("mouseleave", () => { tip.classList.add("hidden"); xh.setAttribute("visibility", "hidden"); });
  },

  /** labels: ["2026-11-01", ...]; series: [{name, data: [n per label]}] stacked. */
  bars(el, labels, series, opts = {}) {
    const w = Math.max(320, el.clientWidth || 900), h = opts.h || 240;
    const pad = { l: 56, r: 10, t: 10, b: 24 }, iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
    const n = labels.length;
    if (!n || !series.length) { el.innerHTML = `<div class="empty">No traffic recorded for this range yet.</div>`; return; }
    const tot = labels.map((_, i) => series.reduce((a, s) => a + (s.data[i] || 0), 0));
    const yMax = this.niceMax(Math.max(...tot, 1) * 1.08);
    const yFmt = opts.yFmt || ((v) => fmt.k(v));
    const xFmt = opts.xFmt || ((l) => l);
    const slot = iw / n, bw = Math.max(2, Math.min(42, slot - Math.max(2, slot * 0.25)));
    const y = (v) => (v / yMax) * ih;
    let s = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" style="display:block">`;
    for (let k = 0; k <= 4; k++) {
      const v = (yMax / 4) * k, yy = pad.t + ih - y(v);
      s += `<line x1="${pad.l}" x2="${w - pad.r}" y1="${yy}" y2="${yy}" stroke="${this.GRID}"/>`;
      s += `<text x="${pad.l - 8}" y="${yy + 4}" fill="${this.AXIS}" font-size="11" text-anchor="end">${esc(yFmt(v))}</text>`;
    }
    const every = Math.ceil(n / Math.max(1, Math.floor(iw / 70)));
    labels.forEach((l, i) => {
      const cx = pad.l + i * slot + slot / 2;
      let base = pad.t + ih;
      series.forEach((sr, k) => {
        const hh = y(sr.data[i] || 0);
        if (hh <= 0) return;
        const top = base - hh;
        s += `<rect x="${cx - bw / 2}" y="${top + 0.5}" width="${bw}" height="${Math.max(0.5, hh - 1)}" rx="${k === series.length - 1 ? 2 : 0}" fill="${this.color(k, sr.name)}"/>`;
        base = top;
      });
      if (i % every === 0) s += `<text x="${cx}" y="${h - 6}" fill="${this.AXIS}" font-size="11" text-anchor="middle">${esc(xFmt(l))}</text>`;
      s += `<rect class="slot" data-i="${i}" x="${pad.l + i * slot}" y="${pad.t}" width="${slot}" height="${ih}" fill="transparent"/>`;
    });
    s += `</svg>`;
    el.innerHTML = this.legend(series.map((x) => x.name)) + `<div class="chartbox">${s}<div class="tip hidden"></div></div>`;
    const box = $(".chartbox", el), svg = $("svg", box), tip = $(".tip", box);
    svg.addEventListener("mousemove", (e) => {
      const sl = e.target.closest(".slot");
      if (!sl) return;
      const i = +sl.dataset.i, r = svg.getBoundingClientRect();
      $$(".slot", svg).forEach((x) => x.setAttribute("fill", x === sl ? "rgba(255,255,255,.04)" : "transparent"));
      tip.innerHTML = `<div class="tt">${esc(opts.tipFmt ? opts.tipFmt(labels[i]) : labels[i])} · ${esc(fmt.n(tot[i]))}</div>`
        + series.map((sr, k) => `<div class="r"><span><i style="background:${this.color(k, sr.name)}"></i>${esc(sr.name)}</span><b>${esc(fmt.n(sr.data[i] || 0))}</b></div>`).join("");
      tip.classList.remove("hidden");
      const left = ((pad.l + (i + 1) * slot) / w) * r.width;
      tip.style.left = left > r.width * 0.65 ? `${((pad.l + i * slot) / w) * r.width - tip.offsetWidth - 8}px` : `${left + 6}px`;
      tip.style.top = "6px";
    });
    svg.addEventListener("mouseleave", () => { tip.classList.add("hidden"); $$(".slot", svg).forEach((x) => x.setAttribute("fill", "transparent")); });
  },

  spark(values, { w = 110, h = 24, color = "#8b90ab", max } = {}) {
    const v = (values || []).filter((x) => x != null);
    if (v.length < 2) return `<span class="sub">–</span>`;
    const mx = max ?? Math.max(...v), mn = max != null ? 0 : Math.min(...v);
    const d = v.map((x, i) => `${i ? "L" : "M"}${((i / (v.length - 1)) * (w - 2) + 1).toFixed(1)},${(h - 3 - ((x - mn) / (mx - mn || 1)) * (h - 6)).toFixed(1)}`).join("");
    return `<svg width="${w}" height="${h}" style="vertical-align:middle" aria-hidden="true"><path d="${d}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
  },
};

fmt.k = (v) => {
  v = Number(v || 0);
  if (v >= 1e9) return (v / 1e9).toFixed(v >= 1e10 ? 0 : 1) + "B";
  if (v >= 1e6) return (v / 1e6).toFixed(v >= 1e7 ? 0 : 1) + "M";
  if (v >= 1e3) return (v / 1e3).toFixed(v >= 1e4 ? 0 : 1) + "k";
  return String(Math.round(v));
};
fmt.pct = (v, d = 1) => (v == null ? "–" : `${Number(v).toFixed(d).replace(/\.0+$/, "")}%`);
fmt.ms = (v) => (v == null ? "–" : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`);
