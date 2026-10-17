// AI Security Monitor 桌面版：「流量與效能」頁——側欄一個項目、頁內三個分頁：
// - 即時（每秒）：app.js 的即時流量頁（pageTraffic）。這裡只包一層，把它的標題換成分頁列，不改它的程式。
// - 最近 1 小時（每分鐘一點）／最近 24 小時（每 5 分鐘一點）：網路速度、各程式的網路流量，以及開啟效能蒐集時的
//   CPU、記憶體、磁碟讀寫、各磁碟區、最吃資源的程式、電池。
// 歷史資料：背景服務（或背景沒在跑時桌面版自己）每分鐘取樣，24 小時歷史存在這台電腦的設定目錄（metrics/history.jsonl）。
// 網址：#traffic＝即時、#traffic/1h、#traffic/24h。
// 和 app.js 共用 invoke／esc／toast／fmtBytes／fmtRate／NET_HINT／PERF_TOGGLE_HINT／pageTraffic，圖表用 chart.js 的 timeChart。
'use strict';

const TRAFFIC_TABS = [
  { id: '', label: '即時（每秒）', hint: '現在的下載／上傳速度與哪個程式在用網路，每秒更新；只在這個分頁開著時量，不會存起來。' },
  { id: '1h', label: '最近 1 小時', hint: '每分鐘一點：網路速度、各程式流量，開啟效能蒐集時還有 CPU、記憶體、磁碟。' },
  { id: '24h', label: '最近 24 小時', hint: '每 5 分鐘一點（這 5 分鐘的平均）：網路速度、各程式流量、CPU、記憶體、磁碟。' },
];
const USAGE_RANGES = [
  { id: '1h', label: '最近 1 小時', hint: '每分鐘一點' },
  { id: '24h', label: '最近 24 小時', hint: '每 5 分鐘一點（這 5 分鐘的平均）' },
];

/** 分頁列（連結，切換時網址跟著變，上一頁／重新整理都回到同一個分頁）。extra 是同一列右邊的說明。 */
function trafficTabs(current, extra = '') {
  const tabs = TRAFFIC_TABS.map(
    (t) =>
      `<a class="segbtn ${t.id === current ? 'on' : ''}" href="#traffic${t.id ? `/${t.id}` : ''}"${t.id === current ? ' aria-current="page"' : ''} title="${esc(t.hint)}">${esc(t.label)}</a>`,
  ).join('');
  return `<div class="tabs-row"><nav class="segs" aria-label="流量與效能的分頁">${tabs}</nav>${extra}</div>`;
}

/** 「流量與效能」：依網址的區塊決定分頁。 */
async function pageTrafficTabs(opts = {}) {
  const tab = opts.section === '1h' || opts.section === '24h' ? opts.section : '';
  if (tab) return pageUsage(tab);
  stopUsageRefresh();
  await pageTraffic();
  // 即時分頁：把即時流量頁的標題換成這一頁的名稱＋分頁列（找不到標題時就放在最上面）
  const head = $main.querySelector('.head');
  const h1 = head?.querySelector('h1');
  if (h1) h1.textContent = '流量與效能';
  if (head) head.insertAdjacentHTML('afterend', trafficTabs(''));
  else $main.insertAdjacentHTML('afterbegin', trafficTabs(''));
}
const PROC_METRICS = [
  { id: 'total', label: '合計' },
  { id: 'rx', label: '下載' },
  { id: 'tx', label: '上傳' },
];
// 前 6 名各一個固定顏色（依整段期間的合計量排名，切換下載／上傳不會換色）；「其他」用灰色虛線
const PROC_COLORS = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)', 'var(--chart-6)'];
const PROC_TOP = 6;
const PROC_HINT = '哪個程式收送了多少資料（依程式名稱合併）。Windows 要以系統管理員執行背景服務才量得到；macOS 用系統內建的 nettop；Linux 量不到。';
const CPU_HINT = '整台電腦的處理器使用率（所有核心平均）。24 小時圖的實線是每 5 分鐘的平均，虛線是這 5 分鐘裡最高的一次取樣。';
const MEM_HINT = '已用＝總量減掉可立即使用的部分（可回收的快取不算已用）。';
const DISKIO_HINT = '所有磁碟每秒讀取、寫入的資料量。';
const VOL_HINT = '各磁碟區用了多少空間（最新一次取樣）。超過 90% 會在 Hub 列成待處理問題。';
const TOP_HINT = '最新一次取樣時，最吃 CPU、最吃記憶體的程式（同名的行程合併計算）。';
const usageState = { range: '1h', metric: 'total', data: null, timer: null };

function stopUsageRefresh() {
  clearTimeout(usageState.timer);
  usageState.timer = null;
}

/** 歷史分頁（range＝1h 或 24h）。 */
async function pageUsage(range) {
  stopUsageRefresh();
  usageState.range = range;
  $main.innerHTML = `
    <div class="head">
      <div><h1>流量與效能</h1><p class="sub">這台電腦最近的網路速度、各程式流量、CPU、記憶體、磁碟。資料留在這台電腦；有加入公司 Hub 時也會回報。</p></div>
    </div>
    ${trafficTabs(range, '<span class="small muted" id="us-source"></span>')}
    <div id="us-body"><p class="muted">載入中…</p></div>`;
  await loadUsage();
}

function segmented(list, current, attr, label) {
  const buttons = list
    .map((x) => `<button type="button" class="segbtn ${x.id === current ? 'on' : ''}" aria-pressed="${x.id === current}" data-${attr}="${x.id}"${x.hint ? ` title="${esc(x.hint)}"` : ''}>${esc(x.label)}</button>`)
    .join('');
  return `<span class="segs" role="group" aria-label="${esc(label)}">${buttons}</span>`;
}

async function loadUsage() {
  stopUsageRefresh();
  const body = document.getElementById('us-body');
  if (!body) return;
  // 重新整理時保留原本的畫面（變淡），不閃
  body.classList.add('loading');
  try {
    const d = await invoke('metrics_history', { range: usageState.range });
    if (!body.isConnected) return;
    usageState.data = d;
    renderUsage(body, d);
  } catch (e) {
    if (body.isConnected) body.innerHTML = `<div class="card"><p class="small" style="color:var(--danger)">${esc(e)}</p></div>`;
  } finally {
    body.classList.remove('loading');
  }
  // 開著這個分頁時每分鐘更新
  if (location.hash === `#traffic/${usageState.range}`) usageState.timer = setTimeout(loadUsage, 60_000);
}

const pick = (pts, f) => pts.map((p) => (p.secs ? f(p) : null));
const sumBytes = (pts, f) => pts.reduce((a, p) => a + (p.secs && f(p) != null ? f(p) * p.secs : 0), 0);

function renderUsage(body, d) {
  const pts = d.points ?? [];
  const times = pts.map((p) => p.ts);
  const stepS = d.step_s;
  const range = USAGE_RANGES.find((r) => r.id === d.range);
  const src = document.getElementById('us-source');
  if (src) {
    src.textContent = `${range?.hint ?? ''}・${d.source === 'background' ? `背景服務每 ${d.interval} 取樣` : '背景自動回報沒在跑：桌面版開著（含縮到系統匣）時每分鐘取樣'}`;
  }
  const emptyText = d.range === '24h' ? '還沒有資料：背景自動回報或桌面版開著時，每 5 分鐘記一筆' : '還沒有資料：累積幾分鐘後會畫出變化';
  const cur = d.current;
  const perf = cur?.perf;
  const card = (id, title, hint, extra = '') =>
    `<div class="card"><h2>${title}${hint ? ` <span class="muted" title="${esc(hint)}">(?)</span>` : ''}</h2>${extra}<div id="${id}"></div></div>`;

  const rxTotal = sumBytes(pts, (p) => p.rx);
  const txTotal = sumBytes(pts, (p) => p.tx);
  let html = card('us-net', '網路速度', NET_HINT, `<p class="small muted us-sum">這段期間合計：下載 <b>${fmtBytes(rxTotal)}</b>、上傳 <b>${fmtBytes(txTotal)}</b></p>`);
  html += `<div class="card"><h2>各程式的網路流量 <span class="muted" title="${esc(PROC_HINT)}">(?)</span></h2>
    <div class="filters" id="us-proc-metric"></div>
    <div id="us-procs"></div><div id="us-proc-table"></div></div>`;
  if (d.performance_enabled) {
    html += `<div class="usage-grid">
      ${card('us-cpu', 'CPU', CPU_HINT, `<p class="small muted us-sum">${perf ? `現在 <b>${chartFmt(perf.cpu_pct, 'pct')}</b>・${esc(perf.cpu_cores)} 個邏輯核心` : '—'}</p>`)}
      ${card('us-mem', '記憶體', MEM_HINT, `<p class="small muted us-sum">${perf ? `現在已用 <b>${fmtBytes(perf.mem_used)}</b>／總量 ${fmtBytes(perf.mem_total)}（${chartFmt((perf.mem_used * 100) / Math.max(1, perf.mem_total), 'pct')}）` : '—'}</p>`)}
      ${card('us-diskio', '磁碟讀寫', DISKIO_HINT)}
      ${card('us-vols', '各磁碟區', VOL_HINT)}
    </div>
    ${card('us-top', '最吃資源的程式（最新一筆）', TOP_HINT)}
    <div id="us-battery-wrap"></div>`;
  } else {
    html += `<div class="card"><h2>效能（CPU、記憶體、磁碟）</h2>
      <p class="small">還沒開啟：目前只統計網路流量。開啟後每分鐘記錄 CPU、記憶體、磁碟用量與讀寫、最吃資源的程式與電池，這一頁就會多出這些圖。</p>
      <label class="row" title="${esc(PERF_TOGGLE_HINT)}"><input type="checkbox" id="us-perf-on" /> <b>蒐集這台電腦的效能（CPU、記憶體、磁碟）</b> <span class="small muted">(?)</span></label>
      <p class="small muted" style="margin:4px 0 0 24px">只會送到這台電腦加入的公司 Hub，Hub 無法從遠端幫你開啟。也可以在「<a class="link" href="#settings">設定</a>」開關。</p>
    </div>`;
  }
  body.innerHTML = html;

  timeChart(document.getElementById('us-net'), {
    label: '網路速度（下載與上傳）',
    format: 'rate',
    times,
    stepS,
    emptyText,
    series: [
      { label: '下載', color: 'var(--chart-1)', values: pick(pts, (p) => p.rx) },
      { label: '上傳', color: 'var(--chart-2)', values: pick(pts, (p) => p.tx) },
    ],
  });
  renderProcs(d, times, stepS, emptyText);

  if (d.performance_enabled) {
    const cpuSeries = [{ label: 'CPU 平均', color: 'var(--chart-1)', values: pick(pts, (p) => p.cpu) }];
    if (d.range === '24h') cpuSeries.push({ label: '最高', color: 'var(--chart-1)', dashed: true, values: pick(pts, (p) => p.cpu_max) });
    timeChart(document.getElementById('us-cpu'), { label: 'CPU 使用率', format: 'pct', times, stepS, emptyText, height: 150, series: cpuSeries });
    timeChart(document.getElementById('us-mem'), {
      label: '記憶體使用率',
      format: 'pct',
      times,
      stepS,
      emptyText,
      height: 150,
      series: [{ label: '記憶體', color: 'var(--chart-1)', values: pick(pts, (p) => (p.mem_total ? (p.mem_used * 100) / p.mem_total : null)) }],
    });
    timeChart(document.getElementById('us-diskio'), {
      label: '磁碟讀寫速率',
      format: 'rate',
      times,
      stepS,
      emptyText,
      height: 150,
      series: [
        { label: '讀取', color: 'var(--chart-1)', values: pick(pts, (p) => p.disk_read) },
        { label: '寫入', color: 'var(--chart-2)', values: pick(pts, (p) => p.disk_write) },
      ],
    });
    renderVolumes(document.getElementById('us-vols'), perf);
    renderTopProcs(document.getElementById('us-top'), perf);
    renderBattery(document.getElementById('us-battery-wrap'), pts, perf, times, stepS, emptyText);
  } else {
    const t = document.getElementById('us-perf-on');
    t.onchange = async () => {
      t.disabled = true;
      try {
        const on = await invoke('set_performance', { enabled: t.checked });
        toast(on ? '已開啟效能蒐集：下一次取樣（約 1 分鐘內）開始有資料' : '已關閉效能蒐集');
        loadUsage();
      } catch (e) {
        t.checked = false;
        t.disabled = false;
        toast(String(e), 8000);
      }
    };
  }
}

/** 各程式：依整段期間的合計量取前 6 名（顏色固定跟著程式），其餘＋沒列進前幾名的合成「其他」。 */
function renderProcs(d, times, stepS, emptyText) {
  const pts = d.points ?? [];
  const box = document.getElementById('us-procs');
  const metricBox = document.getElementById('us-proc-metric');
  const tableBox = document.getElementById('us-proc-table');
  if (!d.has_processes || !pts.some((p) => p.procs)) {
    metricBox.hidden = true;
    box.innerHTML = procHelp(d);
    return;
  }
  const totals = new Map();
  for (const p of pts) {
    for (const x of p.procs ?? []) {
      const t = totals.get(x.name) ?? { rx: 0, tx: 0 };
      t.rx += x.rx * p.secs;
      t.tx += x.tx * p.secs;
      totals.set(x.name, t);
    }
  }
  const ranked = [...totals.entries()].sort((a, b) => b[1].rx + b[1].tx - (a[1].rx + a[1].tx) || a[0].localeCompare(b[0]));
  const top = ranked.slice(0, PROC_TOP).map(([name]) => name);
  const value = (x) => (usageState.metric === 'rx' ? x.rx : usageState.metric === 'tx' ? x.tx : x.rx + x.tx);
  const series = top.map((name, i) => ({
    label: name,
    color: PROC_COLORS[i],
    values: pts.map((p) => (p.procs ? value(p.procs.find((x) => x.name === name) ?? { rx: 0, tx: 0 }) : null)),
  }));
  const otherVals = pts.map((p) => {
    if (!p.procs) return null;
    const rest = p.procs.filter((x) => !top.includes(x.name)).reduce((a, x) => a + value(x), 0);
    return rest + (p.procs_other ? value(p.procs_other) : 0);
  });
  if (otherVals.some((v) => v)) series.push({ label: '其他程式', color: 'var(--chart-axis)', dashed: true, values: otherVals });
  const draw = () => {
    metricBox.innerHTML = segmented(PROC_METRICS, usageState.metric, 'metric', '顯示');
    for (const b of metricBox.querySelectorAll('[data-metric]')) {
      b.onclick = () => {
        usageState.metric = b.dataset.metric;
        renderProcs(d, times, stepS, emptyText);
      };
    }
  };
  draw();
  const name = { total: '下載＋上傳', rx: '下載', tx: '上傳' }[usageState.metric];
  timeChart(box, { label: `各程式的${name}速率`, format: 'rate', times, stepS, emptyText, height: 210, series });
  // 這段期間各程式的量（前 10 名）
  const rows = ranked.slice(0, 10);
  tableBox.innerHTML = `<table class="us-proc-table"><thead><tr><th>程式</th><th class="num">下載</th><th class="num">上傳</th><th class="num">合計</th></tr></thead><tbody></tbody></table>
    <p class="small muted" style="margin:6px 0 0">這段期間的量（前 10 名）。${d.platform === 'windows' ? 'Windows 只算 TCP 連線的資料，不含 UDP。' : ''}</p>`;
  const tb = tableBox.querySelector('tbody');
  for (const [n, t] of rows) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    const i = top.indexOf(n);
    if (i >= 0) td.appendChild(lineKey(PROC_COLORS[i], false));
    td.appendChild(document.createTextNode(` ${n}`));
    tr.appendChild(td);
    for (const v of [t.rx, t.tx, t.rx + t.tx]) {
      const c = document.createElement('td');
      c.className = 'num';
      c.textContent = fmtBytes(v);
      tr.appendChild(c);
    }
    tb.appendChild(tr);
  }
}

function procHelp(d) {
  if (d.process_network === false) {
    return '<p class="small">各程式的流量統計已關閉（設定 <span class="mono">metrics.process_network</span>）。要開啟：<span class="mono">ai-security-monitor config set metrics.process_network true</span>。</p>';
  }
  const win = `<li><b>Windows</b>：要以<b>系統管理員</b>執行背景服務才量得到。用「以系統管理員身分執行」開 PowerShell，執行
      <span class="mono">ai-security-monitor service install --system --yes</span>（改成開機時啟動的系統服務），幾分鐘後就會有資料。</li>`;
  const mac = '<li><b>macOS</b>：會自動用系統內建的 nettop 量，不用另外設定。</li>';
  const linux = '<li><b>Linux</b>：目前量不到各程式的流量（需要 eBPF）；可以看「<a class="link" href="#connections">連線</a>」頁哪些程式在連網。</li>';
  const order = d.platform === 'macos' ? [mac, win, linux] : d.platform === 'linux' ? [linux, win, mac] : [win, mac, linux];
  return `<div class="small"><p style="margin:0 0 6px"><b>這台電腦目前量不到各程式的流量。</b>上面的網路速度一樣會統計。</p>
    <ul style="margin:0;padding-left:18px">${order.join('')}</ul></div>`;
}

function renderVolumes(box, perf) {
  const vols = (perf?.disks ?? []).filter((v) => v.total > 0);
  if (!vols.length) {
    box.innerHTML = '<p class="small muted">還沒有資料。</p>';
    return;
  }
  box.innerHTML = vols
    .map((v) => {
      const pct = (v.used * 100) / v.total;
      const hot = pct >= 90;
      return `<div class="vol">
        <div class="vol-head"><b class="mono">${esc(v.mount)}</b><span class="small">${chartFmt(pct, 'pct')}・${fmtBytes(v.used)}／${fmtBytes(v.total)}${hot ? ' <span class="chip high">快滿了</span>' : ''}</span></div>
        <div class="meter${hot ? ' hot' : ''}" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(pct)}" aria-label="${esc(`${v.mount} 已用 ${Math.round(pct)}%`)}"><i style="width:${Math.min(100, pct).toFixed(1)}%"></i></div>
      </div>`;
    })
    .join('');
}

function renderTopProcs(box, perf) {
  if (!perf) {
    box.innerHTML = '<p class="small muted">還沒有資料。</p>';
    return;
  }
  const rows = (list, kind) =>
    (list ?? [])
      .map(
        (p) => `<tr><td>${esc(p.name)}${p.count > 1 ? ` <span class="muted small">× ${esc(p.count)}</span>` : ''}</td>
          <td class="num">${kind === 'cpu' ? `<b>${chartFmt(p.cpu_pct, 'pct')}</b>` : chartFmt(p.cpu_pct, 'pct')}</td>
          <td class="num">${kind === 'mem' ? `<b>${fmtBytes(p.rss)}</b>` : fmtBytes(p.rss)}</td></tr>`,
      )
      .join('') || '<tr><td colspan="3" class="muted">—</td></tr>';
  const head = '<thead><tr><th>程式</th><th class="num">CPU</th><th class="num">記憶體</th></tr></thead>';
  box.innerHTML = `<div class="usage-grid tight">
    <div><h3 class="sub-h" style="margin-top:0">最吃 CPU</h3><table>${head}<tbody>${rows(perf.top_cpu, 'cpu')}</tbody></table></div>
    <div><h3 class="sub-h" style="margin-top:0">最吃記憶體</h3><table>${head}<tbody>${rows(perf.top_mem, 'mem')}</tbody></table></div>
  </div>`;
}

function renderBattery(wrap, pts, perf, times, stepS, emptyText) {
  const b = perf?.battery;
  const values = pick(pts, (p) => p.battery ?? null);
  if (!b && !values.some((v) => v != null)) {
    wrap.innerHTML = '';
    return;
  }
  const state = b ? (b.charging ? '充電中' : b.plugged ? '接著電源' : '用電池') : '';
  wrap.innerHTML = `<div class="card"><h2>電池</h2><p class="small muted us-sum">${b ? `現在 <b>${esc(b.percent)}%</b>・${state}` : '—'}</p><div id="us-battery"></div></div>`;
  timeChart(document.getElementById('us-battery'), {
    label: '電池電量',
    format: 'pct',
    times,
    stepS,
    emptyText,
    height: 130,
    series: [{ label: '電量', color: 'var(--chart-3)', values }],
  });
}
