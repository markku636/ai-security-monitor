// AI Security Monitor 桌面版：時間序列折線圖（純 SVG、純 JS，不用圖表套件）。
// 行為照 Hub 的 components/charts/TimeChart.tsx：一條 y 軸、2px 線、好讀的 y 軸刻度（位元組用 1024 的倍數）、
// 滑過（或聚焦後用左右鍵）顯示十字線與每條線在那個時間的值；兩條以上有圖例（文字＋線段，不只靠顏色）；
// 附一份給螢幕閱讀器的表格。顏色用 style.css 的 --chart-* token，深淺色自動切換。
// 序列名稱（程式名稱）一律用 textContent 放進 DOM，不經 innerHTML。
// 和 app.js 共用 fmtBytes／fmtRate（app.js 定義）；這個檔先載入，只定義函式。
'use strict';

const CHART_PAD = { l: 64, r: 12, t: 10, b: 22 };

/** 刻度與數值的格式：rate＝bytes/s、bytes、pct（0–100）、number。 */
function chartFmt(v, f, axis = false) {
  if (v == null || !Number.isFinite(v)) return '—';
  if (f === 'rate' || f === 'bytes') {
    const s = f === 'rate' ? fmtRate(v) : fmtBytes(v);
    return axis ? s.replace('.0 ', ' ') : s;
  }
  if (f === 'pct') return `${v >= 10 || axis ? Math.round(v) : v.toFixed(1)}%`;
  return v >= 10 ? String(Math.round(v)) : v.toFixed(1);
}

/** 最大值往上取到好讀的刻度（1、2、5 × 10^k；位元組用 1024 的倍數；百分比固定 100）。 */
function niceMax(v, f) {
  if (f === 'pct') return 100;
  if (f === 'rate' || f === 'bytes') {
    // 最少 1 KB：沒有資料或幾乎沒流量時，刻度也不會出現「0.5 B」這種值
    v = Math.max(v || 0, 1024);
    let unit = 1;
    while (v / unit >= 1024) unit *= 1024;
    const x = v / unit;
    const step = [1, 2, 4, 5, 8, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 1024].find((s) => s >= x) ?? 1024;
    return step * unit;
  }
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  return ([1, 2, 5, 10].find((s) => s * p >= v) ?? 10) * p;
}

const pad2 = (n) => String(n).padStart(2, '0');
const hhmm = (d) => `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;

/** 時間點（本機時間）。stepS > 60 時顯示一段時間（14:05–14:10）。 */
function chartTime(iso, stepS = 60, withDate = false) {
  const d = new Date(iso);
  const end = new Date(d.getTime() + stepS * 1000);
  const day = withDate ? `${d.getMonth() + 1}/${d.getDate()} ` : '';
  return stepS > 60 ? `${day}${hhmm(d)}–${hhmm(end)}` : `${day}${hhmm(d)}`;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function lineKey(color, dashed) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', '16');
  svg.setAttribute('height', '8');
  svg.setAttribute('aria-hidden', 'true');
  const l = document.createElementNS(ns, 'line');
  for (const [k, v] of Object.entries({ x1: 0, x2: 16, y1: 4, y2: 4, stroke: color, 'stroke-width': 2 })) l.setAttribute(k, v);
  if (dashed) l.setAttribute('stroke-dasharray', '4 3');
  svg.appendChild(l);
  return svg;
}

/**
 * 在 host 裡畫一張時間序列圖。
 * opts: { times: ISO[], series: [{label, color, values: (number|null)[], dashed?}], format, height?, label, stepS?, emptyText? }
 */
function timeChart(host, opts) {
  const { times, series, format, height = 170, label, stepS = 60, emptyText = '這段期間沒有資料' } = opts;
  const n = times.length;
  const all = series.flatMap((s) => s.values).filter((v) => v != null && Number.isFinite(v));
  const empty = all.length === 0;
  const max = niceMax(all.length ? Math.max(...all) : 0, format);
  const latest = (s) => [...s.values].reverse().find((v) => v != null);
  const multiDay = n > 1 && new Date(times[0]).getDate() !== new Date(times[n - 1]).getDate();

  host.textContent = '';
  const fig = el('figure', 'tchart');
  if (series.length > 1) {
    const cap = el('figcaption', 'tchart-legend');
    for (const s of series) {
      const item = el('span', 'tchart-key');
      item.appendChild(lineKey(s.color, s.dashed));
      item.appendChild(document.createTextNode(s.label));
      item.appendChild(el('span', 'tchart-key-val', chartFmt(latest(s), format)));
      cap.appendChild(item);
    }
    fig.appendChild(cap);
  }
  const box = el('div', 'tchart-box');
  box.style.height = `${height}px`;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `${label}（滑過或用左右鍵看各時間點的值）`);
  svg.setAttribute('tabindex', '0');
  svg.setAttribute('class', 'tchart-svg');
  const tip = el('div', 'tchart-tip');
  tip.hidden = true;
  box.append(svg, tip);
  fig.appendChild(box);

  // 給螢幕閱讀器的表格（點很多時抽樣，最多約 48 列）
  const table = el('table', 'sr-only');
  table.appendChild(el('caption', null, label));
  const hr = el('tr');
  hr.appendChild(el('th', null, '時間'));
  for (const s of series) hr.appendChild(el('th', null, s.label));
  table.appendChild(el('thead')).appendChild(hr);
  const tb = el('tbody');
  const every = Math.max(1, Math.ceil(n / 48));
  times.forEach((t, i) => {
    if (i % every) return;
    const tr = el('tr');
    tr.appendChild(el('td', null, chartTime(t, stepS, multiDay)));
    for (const s of series) tr.appendChild(el('td', null, chartFmt(s.values[i], format)));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  fig.appendChild(table);
  host.appendChild(fig);

  let width = Math.max(240, Math.round(box.clientWidth || 640));
  let hover = null;
  const geo = () => {
    const w = Math.max(1, width - CHART_PAD.l - CHART_PAD.r);
    const h = Math.max(1, height - CHART_PAD.t - CHART_PAD.b);
    const x = (i) => CHART_PAD.l + (n <= 1 ? w / 2 : (i / (n - 1)) * w);
    const y = (v) => CHART_PAD.t + h - (Math.min(v, max) / max) * h;
    return { w, h, x, y };
  };

  function draw() {
    const { w, h, x, y } = geo();
    svg.setAttribute('width', width);
    svg.setAttribute('height', height);
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    let out = '';
    for (const f of [0, 0.5, 1]) {
      const yy = CHART_PAD.t + h - f * h;
      out += `<line x1="${CHART_PAD.l}" x2="${CHART_PAD.l + w}" y1="${yy}" y2="${yy}" stroke="var(--chart-grid)" stroke-width="1"/>`;
      out += `<text x="${CHART_PAD.l - 6}" y="${yy + 4}" text-anchor="end" class="tchart-axis">${esc(chartFmt(max * f, format, true))}</text>`;
    }
    const ticks = n > 1 ? [...new Set([0, Math.round((n - 1) / 3), Math.round(((n - 1) * 2) / 3), n - 1])] : [0];
    for (const i of ticks) {
      if (!times[i]) continue;
      const anchor = i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle';
      out += `<text x="${x(i)}" y="${height - 6}" text-anchor="${anchor}" class="tchart-axis">${esc(hhmm(new Date(times[i])))}</text>`;
    }
    series.forEach((s) => {
      let d = '';
      let pen = false;
      s.values.forEach((v, i) => {
        if (v == null || !Number.isFinite(v)) {
          pen = false;
          return;
        }
        d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
        pen = true;
      });
      if (d) out += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"${s.dashed ? ' stroke-dasharray="4 3"' : ''}/>`;
      // 前後都沒有資料的單獨一點畫成圓點，不然看不到
      s.values.forEach((v, i) => {
        if (v != null && s.values[i - 1] == null && s.values[i + 1] == null) out += `<circle cx="${x(i)}" cy="${y(v)}" r="2.5" fill="${s.color}"/>`;
      });
    });
    if (empty) out += `<text x="${CHART_PAD.l + w / 2}" y="${CHART_PAD.t + h / 2}" text-anchor="middle" class="tchart-empty">${esc(emptyText)}</text>`;
    out += '<g class="tchart-hover" pointer-events="none"></g>';
    svg.innerHTML = out;
    drawHover();
  }

  function drawHover() {
    const g = svg.querySelector('.tchart-hover');
    if (!g) return;
    if (hover == null || empty) {
      g.innerHTML = '';
      tip.hidden = true;
      return;
    }
    const { h, x, y } = geo();
    let out = `<line x1="${x(hover)}" x2="${x(hover)}" y1="${CHART_PAD.t}" y2="${CHART_PAD.t + h}" stroke="var(--chart-axis)" stroke-width="1" stroke-dasharray="2 2"/>`;
    for (const s of series) {
      const v = s.values[hover];
      if (v != null && Number.isFinite(v)) out += `<circle cx="${x(hover)}" cy="${y(v)}" r="4" fill="${s.color}" stroke="var(--chart-surface)" stroke-width="2"/>`;
    }
    g.innerHTML = out;
    tip.textContent = '';
    tip.appendChild(el('div', 'tchart-tip-time', chartTime(times[hover], stepS, true)));
    for (const s of series) {
      const row = el('div', 'tchart-tip-row');
      const name = el('span', 'tchart-tip-name');
      name.appendChild(lineKey(s.color, s.dashed));
      name.appendChild(document.createTextNode(s.label));
      row.append(name, el('b', 'tchart-tip-val', chartFmt(s.values[hover], format)));
      tip.appendChild(row);
    }
    tip.hidden = false;
    const px = x(hover);
    tip.style.left = '';
    tip.style.right = '';
    if (px > width / 2) tip.style.right = `${width - px + 10}px`;
    else tip.style.left = `${px + 10}px`;
  }

  const setHover = (i) => {
    hover = i == null || n < 1 ? null : Math.max(0, Math.min(n - 1, i));
    drawHover();
  };
  svg.addEventListener('pointermove', (e) => {
    const r = svg.getBoundingClientRect();
    const { w } = geo();
    const px = ((e.clientX - r.left) / r.width) * width;
    setHover(Math.round(((px - CHART_PAD.l) / w) * (n - 1)));
  });
  svg.addEventListener('pointerleave', () => setHover(null));
  svg.addEventListener('focus', () => {
    const last = times.map((_, i) => i).reverse().find((i) => series.some((s) => s.values[i] != null));
    setHover(last ?? n - 1);
  });
  svg.addEventListener('blur', () => setHover(null));
  svg.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      setHover((hover ?? n - 1) + (e.key === 'ArrowLeft' ? -1 : 1));
    } else if (e.key === 'Escape') setHover(null);
  });

  draw();
  if (typeof ResizeObserver !== 'undefined') {
    const ro = new ResizeObserver((entries) => {
      if (!box.isConnected) return ro.disconnect();
      const nw = Math.max(240, Math.round(entries[0].contentRect.width));
      if (nw !== width) {
        width = nw;
        draw();
      }
    });
    ro.observe(box);
  }
}
