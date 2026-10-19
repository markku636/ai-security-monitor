// AI Security Monitor 桌面版介面：純 HTML／JS，透過 Tauri 指令呼叫 ai-security-monitor 程式庫。
'use strict';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $main = document.getElementById('main');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const VERDICT = { dangerous: '危險', suspicious: '可疑', unknown: '未知', safe: '安全' };
const DIRECTION = { outbound: '對外', inbound: '對內', listening: '監聽', local: '本機' };
const SEVERITY = { critical: '嚴重', high: '高', medium: '中', low: '低', info: '資訊' };
const ANOMALY = {
  new_destination: '新目的地',
  new_listener: '新的監聽 port',
  risky_port: '高風險 port',
  beaconing: '週期性連線（疑似 beacon）',
  shell_with_network: '命令列／腳本程式連網',
  temp_dir_process: '從暫存目錄執行',
  unknown_exe: '找不到執行檔',
  exposed_listener: '對所有介面開放',
  failed_logon_burst_source: '大量登入失敗來源',
  tor_exit: 'Tor 出口節點',
  off_hours: '非上班時間',
  high_volume_upload: '大量上傳',
  plaintext_protocol: '明文協定',
};

function toast(msg, ms = 3500) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), ms);
}

// 右側滑出的分析面板（IP 分析、網域分析）：✕ 或 Esc 關閉，換頁時自動關。
// 回傳內容區；非同步查完要寫入前先確認 body.isConnected（期間換查別的就不寫）。
function openDrawer(title, body) {
  let d = document.getElementById('drawer');
  if (!d) {
    d = document.createElement('aside');
    d.id = 'drawer';
    d.className = 'drawer';
    d.setAttribute('role', 'dialog');
    document.body.appendChild(d);
  }
  d.setAttribute('aria-label', title);
  d.hidden = false;
  d.innerHTML = `<div class="drawer-head"><h2>${esc(title)}</h2><button class="icon-btn" id="drawer-close" title="關閉（Esc）" aria-label="關閉">✕</button></div><div id="drawer-body">${body}</div>`;
  document.getElementById('drawer-close').onclick = closeDrawer;
  return document.getElementById('drawer-body');
}

function closeDrawer() {
  const d = document.getElementById('drawer');
  if (d && !d.hidden) {
    d.hidden = true;
    d.innerHTML = '';
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
  // Ctrl+F 或 /：跳到這頁的搜尋框
  const box = document.querySelector('#main [data-search]');
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName ?? '');
  if (box && ((e.key === 'f' && (e.ctrlKey || e.metaKey)) || (e.key === '/' && !typing))) {
    e.preventDefault();
    box.focus();
    box.select();
  }
});
window.addEventListener('hashchange', closeDrawer);

const isIpLike = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(':') && s.length > 2);
const isDomainLike = (s) => !/\s/.test(s) && /^(?:[a-z][a-z0-9+.-]*:\/\/)?[^/\s]+\.[a-z0-9-]{2,}(?:[:/].*)?$/i.test(s);

function ago(iso) {
  if (!iso) return '—';
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return '剛剛';
  if (s < 3600) return `${Math.floor(s / 60)} 分鐘前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小時前`;
  return `${Math.floor(s / 86400)} 天前`;
}

const endpoint = (ip, port) => (ip ? (ip.includes(':') ? `[${ip}]` : ip) + (port != null ? `:${port}` : '') : '—');

function reasonHtml(r) {
  switch (r.type) {
    case 'intel_hit':
      return `<span class="reason intel" data-url="${esc(r.source_url)}" title="${esc(`${r.vendor} · ${r.name}\n信心 ${r.confidence}%\n授權：${r.license ?? ''}\n點一下開啟原始清單`)}"><span class="k">情資</span>${esc(r.vendor)} ${esc(r.confidence)}%</span>`;
    case 'anomaly':
      return `<span class="reason behavior" title="${esc(`ai-security-monitor 自己的行為判斷，不是情資來源\n${r.detail ?? ''}`)}"><span class="k">行為</span>${esc(ANOMALY[r.kind] ?? r.kind)}</span>`;
    case 'reputation':
      return `<span class="reason plain" title="${esc(r.detail)}">${esc(r.provider)} 名譽 ${esc(r.score)}</span>`;
    case 'known_good':
      return `<span class="reason good" title="${esc(r.detail)}">已知良好：${esc(r.list)}</span>`;
    case 'allowlisted':
      return `<span class="reason good">白名單</span>`;
    case 'private_network':
      return `<span class="reason plain">私有網路</span>`;
    case 'loopback':
      return `<span class="reason plain">本機迴路</span>`;
    default:
      return `<span class="reason plain">${esc(r.type)}</span>`;
  }
}

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-url]');
  if (el && el.dataset.url) {
    e.preventDefault();
    invoke('open_url', { url: el.dataset.url }).catch((err) => toast(String(err)));
  }
  const ip = e.target.closest('[data-ip]');
  if (ip) {
    e.preventDefault();
    showIp(ip.dataset.ip);
  }
  const dom = e.target.closest('[data-domain]');
  if (dom) {
    e.preventDefault();
    showDomain(dom.dataset.domain);
  }
});

// ---------------- 總覽 ----------------
async function pageOverview() {
  $main.innerHTML = `<h1>總覽</h1><p class="sub">載入中…</p>`;
  const o = await invoke('overview');
  document.getElementById('brand-host').textContent = o.hostname || o.report?.hostname || '本機';
  document.getElementById('side-version').textContent = `ai-security-monitor ${o.version}`;
  document.getElementById('side-status').textContent = o.watcher_running ? '背景服務執行中' : '背景服務沒有在跑';
  const r = o.report;
  const s = r?.score;
  const bar = (label, v) => `<div class="stat"><div class="label">${label}</div><div class="value">${v ?? '—'}</div><div class="bar"><i style="width:${v ?? 0}%"></i></div></div>`;
  const intelOld = !o.intel.checked_at || Date.now() - Date.parse(o.intel.checked_at) > 6 * 3600e3;
  $main.innerHTML = `
    <div class="head">
      <div><h1>總覽</h1><p class="sub">這台電腦目前的安全狀況（資料與背景的 ai-security-monitor 共用）。</p></div>
      <div class="row">
        <button class="btn primary" id="scan">立即掃描</button>
        <button class="btn" id="upd">更新情資</button>
        ${o.hub_url ? `<button class="btn" data-url="${esc(o.hub_url)}">開啟 Security Hub</button>` : ''}
      </div>
    </div>
    <div class="grid">
      <div class="stat"><div class="label">安全分數</div><div class="score">${s?.overall ?? '—'}</div><div class="hint">${r ? `最後掃描 ${ago(r.finished_at)}${r.partial ? '（權限不足，部分資料缺）' : ''}` : '還沒掃描過'}</div></div>
      ${bar('連線', s?.connections)}${bar('曝露', s?.exposure)}${bar('漏洞', s?.vulns)}${bar('安全設定', s?.hardening)}
    </div>
    <div class="grid">
      <div class="stat"><div class="label">嚴重＋高</div><div class="value" style="color:var(--danger)">${r ? r.counts.critical + r.counts.high : '—'}</div><div class="hint"><a class="link" href="#findings">看掃描結果</a></div></div>
      <div class="stat"><div class="label">中</div><div class="value">${r ? r.counts.medium : '—'}</div><div class="hint">低 ${r?.counts.low ?? '—'}、資訊 ${r?.counts.info ?? '—'}</div></div>
      <div class="stat"><div class="label">威脅情資</div><div class="value">${o.intel.ok}/${o.intel.total}</div><div class="hint">${o.intel.checked_at ? `最後更新 ${ago(o.intel.checked_at)}` : '還沒下載'}${o.intel.source === 'hub' ? '・從 Hub' : o.intel.source === 'vendor' ? '・直接找廠商' : ''}${intelOld ? ' <span class="chip medium">過期</span>' : ''}</div></div>
      <div class="stat"><div class="label">Security Hub</div><div class="value" style="font-size:15px;padding-top:8px">${o.hub_url ? '已註冊' : '未註冊'}</div><div class="hint">${o.hub_url ? `<span class="mono">${esc(o.hub_url)}</span>` : `<a class="link" href="${HUB_SECTION}">尋找同網段的 Hub</a>`}</div></div>
    </div>
    <div class="grid" id="ov-metrics"><div class="stat"><div class="label">網路</div><div class="hint">載入中…</div></div></div>
    <div class="card" id="ov-upload" hidden></div>
    <div class="card"><h2>危險與可疑連線</h2><div id="ov-conn" class="muted">載入中…</div></div>`;
  renderUploadCard(document.getElementById('ov-upload'));
  document.getElementById('scan').onclick = () => scanNow();
  document.getElementById('upd').onclick = () => updateIntel(false);
  loadMetrics();
  try {
    const c = await invoke('connections');
    const bad = c.connections.filter((x) => x.verdict.level === 'dangerous' || x.verdict.level === 'suspicious');
    document.getElementById('ov-conn').innerHTML = bad.length
      ? connTable(groupConns(bad).slice(0, 8), { sortable: false })
      : '<p class="muted">目前沒有可疑或危險的連線。</p>';
  } catch (e) {
    document.getElementById('ov-conn').textContent = String(e);
  }
}

// ---------------- 網路流量與效能（總覽的卡片） ----------------
const fmtBytes = (n) => {
  if (n == null || !Number.isFinite(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Math.max(0, n);
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${Math.round(v)} B` : `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
};
const fmtRate = (n) => (n == null ? '—' : `${fmtBytes(n)}/s`);
const fmtPct = (n) => (n == null ? '—' : `${Math.round(n)}%`);

/** 小折線圖（一條或兩條線；pct 時固定 0–100）。點下去到「流量與效能」頁看完整的圖。 */
function sparkline(series, { pct = false, label = '' } = {}) {
  const W = 160;
  const H = 36;
  const all = series.flatMap((s) => s.values).filter((v) => v != null);
  if (all.length < 2) return '<a class="spark-link spark-empty" href="#traffic/1h" title="看「流量與效能」頁">累積幾分鐘後會畫出變化</a>';
  const max = pct ? 100 : Math.max(...all, 1);
  const n = Math.max(...series.map((s) => s.values.length));
  const x = (i) => (n <= 1 ? W / 2 : (i / (n - 1)) * (W - 2) + 1);
  const y = (v) => H - 2 - (Math.min(v, max) / max) * (H - 4);
  const lines = series
    .map((s) => {
      let d = '';
      let pen = false;
      s.values.forEach((v, i) => {
        if (v == null) { pen = false; return; }
        d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
        pen = true;
      });
      return d ? `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>` : '';
    })
    .join('');
  return `<a class="spark-link" href="#traffic/1h" title="點一下看「流量與效能」的完整圖表" aria-label="${esc(`${label}：看「流量與效能」的完整圖表`)}"><svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">${lines}</svg></a>`;
}

let metricsTimer = null;
async function loadMetrics() {
  clearTimeout(metricsTimer);
  const el = document.getElementById('ov-metrics');
  if (!el) return;
  try {
    const m = await invoke('metrics_now');
    renderMetrics(el, m);
  } catch (e) {
    el.innerHTML = `<div class="stat"><div class="label">網路</div><div class="hint">${esc(e)}</div></div>`;
  }
  // 開著總覽時每 10 秒更新（背景服務的樣本是每分鐘一個）
  if (location.hash === '' || location.hash === '#overview') metricsTimer = setTimeout(loadMetrics, 10000);
}

const NET_HINT = '這台電腦實體網卡的上傳／下載速度（VPN、Docker、WSL 這類虛擬網卡不重複計算）。網路流量一律統計，有加入公司 Hub 時會一起回報。';
const PERF_HINT = '要蒐集 CPU、記憶體、磁碟才會顯示；資料只會送到這台電腦加入的公司 Hub。到「設定」開啟。';

function renderMetrics(el, m) {
  const pts = m.points ?? [];
  const cur = m.current;
  const secs = Math.max(1, cur?.interval_s ?? 1);
  const rx = cur ? cur.net.rx_bytes / secs : null;
  const tx = cur ? cur.net.tx_bytes / secs : null;
  const src = m.source === 'background' ? `背景服務每 ${esc(m.interval)} 取樣` : '桌面版開著時取樣';
  const net = `<div class="stat metric" title="${esc(`${NET_HINT}
${src}`)}">
    <div class="label">網路（現在）<span class="muted"> (?)</span></div>
    <div class="value small-value"><span class="dl">↓ ${fmtRate(rx)}</span> <span class="ul">↑ ${fmtRate(tx)}</span></div>
    ${sparkline([{ values: pts.map((p) => p.rx), color: 'var(--chart-1)' }, { values: pts.map((p) => p.tx), color: 'var(--chart-2)' }], { label: '下載與上傳速率' })}
    <div class="hint"><span class="key dl">下載</span> <span class="key ul">上傳</span></div>
  </div>`;
  if (!m.performance_enabled) {
    el.innerHTML = `${net}<div class="stat" title="${esc(PERF_HINT)}">
      <div class="label">效能（CPU、記憶體、磁碟）</div>
      <div class="value" style="font-size:15px;padding-top:8px">未開啟</div>
      <div class="hint"><a class="link" href="#settings">到設定開啟</a>・只會送到這台加入的 Hub</div>
    </div>`;
    return;
  }
  const p = cur?.perf;
  const memPct = p && p.mem_total ? (p.mem_used * 100) / p.mem_total : null;
  const disk = p?.disks?.filter((d) => d.total > 0).map((d) => ({ ...d, pct: (d.used * 100) / d.total })).sort((a, b) => b.pct - a.pct)[0];
  const card = (label, value, key, sub, hint) => `<div class="stat metric" title="${esc(hint)}">
    <div class="label">${label}<span class="muted"> (?)</span></div>
    <div class="value small-value${value != null && value >= 90 ? ' hot' : ''}">${fmtPct(value)}</div>
    ${sparkline([{ values: pts.map((x) => x[key]), color: 'var(--chart-1)' }], { pct: true, label })}
    <div class="hint">${sub}</div>
  </div>`;
  el.innerHTML =
    net +
    card('CPU', p?.cpu_pct, 'cpu', p ? `${p.cpu_cores} 個邏輯核心` : '—', '整台電腦的處理器使用率（所有核心平均）。') +
    card('記憶體', memPct, 'mem', p ? `${fmtBytes(p.mem_used)}／${fmtBytes(p.mem_total)}` : '—', '已用＝總量減掉可立即使用的部分（可回收的快取不算已用）。') +
    card('磁碟（最滿的磁碟區）', disk?.pct, 'disk', disk ? `${esc(disk.mount)}：${fmtBytes(disk.used)}／${fmtBytes(disk.total)}` : '—', '各磁碟區裡用得最滿的那個。超過 90% 會在 Hub 列成待處理問題。');
}

async function scanNow() {
  const b = document.getElementById('scan');
  if (b) { b.disabled = true; b.innerHTML = '<span class="spin"></span> 掃描中…'; }
  toast('掃描中，約 10–60 秒…', 60000);
  try {
    const r = await invoke('scan_now');
    toast(`掃描完成：${r.findings.length} 筆問題，總分 ${r.score.overall}`);
    route();
  } catch (e) {
    toast(`掃描失敗：${e}`);
    if (b) { b.disabled = false; b.textContent = '立即掃描'; }
  }
}

async function updateIntel(force) {
  toast('更新情資中…', 120000);
  try {
    const outs = await invoke('intel_update', { force });
    const n = (s) => outs.filter((o) => o.status === s).length;
    const hub = outs.filter((o) => o.source === 'hub').length;
    toast(`情資：${n('updated')} 個有新資料、${n('not_modified') + n('fresh')} 個沒變、${n('error')} 個失敗${hub ? `（${hub} 個從 Hub）` : ''}`);
    route();
  } catch (e) {
    toast(`更新失敗：${e}`);
  }
}

// ---------------- 連線 ----------------
/** 同一行程連到同一遠端（同判定、同方向）合併成一列。 */
function groupConns(list) {
  const m = new Map();
  for (const c of list) {
    const k = [c.verdict.level, c.direction, c.remote_ip ?? c.local_ip, c.remote_port ?? c.local_port, c.process?.name ?? ''].join('|');
    const g = m.get(k);
    if (g) g.n += 1;
    else m.set(k, { c, n: 1 });
  }
  const rank = { dangerous: 0, suspicious: 1, unknown: 2, safe: 3 };
  return [...m.values()].sort((a, b) => rank[a.c.verdict.level] - rank[b.c.verdict.level] || b.n - a.n);
}

// 欄位排序：點表頭切換，同一欄再點一次反向。
const CONN_COLS = [
  ['verdict', '判定'],
  ['direction', '方向'],
  ['remote', '遠端'],
  ['n', '條數'],
  ['country', '國家／組織'],
  ['process', '程式'],
  ['reason', '理由與來源'],
];
const VERDICT_RANK = { dangerous: 0, suspicious: 1, unknown: 2, safe: 3 };
const DIR_RANK = { outbound: 0, inbound: 1, listening: 2, local: 3 };

/** IP 排序鍵：IPv4 補零成可比較字串，IPv6 放後面。 */
function ipKey(ip) {
  if (!ip) return '~';
  if (ip.includes('.') && !ip.includes(':')) return ip.split('.').map((x) => x.padStart(3, '0')).join('.');
  return `~${ip}`;
}

function reasonKind(c) {
  const r = c.verdict.reasons ?? [];
  if (r.some((x) => x.type === 'intel_hit')) return 'intel';
  if (r.some((x) => x.type === 'anomaly')) return 'behavior';
  return 'none';
}

function sortKey(key, { c, n }) {
  switch (key) {
    case 'verdict':
      return VERDICT_RANK[c.verdict.level] ?? 9;
    case 'direction':
      return DIR_RANK[c.direction] ?? 9;
    case 'remote':
      return c.direction === 'listening' ? `${ipKey(c.local_ip)}:${String(c.local_port).padStart(5, '0')}` : `${ipKey(c.remote_ip)}:${String(c.remote_port ?? 0).padStart(5, '0')}`;
    case 'n':
      return n;
    case 'country':
      return `${c.geo?.country ?? '~'} ${c.geo?.org ?? ''}`.toLowerCase();
    case 'process':
      return (c.process?.name ?? '~').toLowerCase();
    case 'reason':
      return { intel: 0, behavior: 1, none: 2 }[reasonKind(c)] * 100 - (c.verdict.reasons ?? []).length;
    default:
      return 0;
  }
}

function sortGroups(groups) {
  const { key, dir } = connState.sort;
  return groups.slice().sort((a, b) => {
    const x = sortKey(key, a);
    const y = sortKey(key, b);
    const cmp = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
    // 同值時用「判定、條數多的在前」當第二排序，結果穩定
    return cmp * dir || (VERDICT_RANK[a.c.verdict.level] ?? 9) - (VERDICT_RANK[b.c.verdict.level] ?? 9) || b.n - a.n;
  });
}

function connTable(rows, { sortable = true } = {}) {
  const { key, dir } = connState.sort;
  const th = ([k, label]) =>
    !sortable ? `<th>${label}</th>` :
    `<th class="sortable" data-sort="${k}" title="點一下依「${label}」排序，再點一次反向">${label}${k === key ? `<span class="sort-ind">${dir > 0 ? '▲' : '▼'}</span>` : ''}</th>`;
  return `<table><thead><tr>${CONN_COLS.map(th).join('')}</tr></thead><tbody>${rows
    .map(({ c, n }) => {
      const remote = c.direction === 'listening'
        ? `<span class="mono">${esc(endpoint(c.local_ip, c.local_port))}</span>`
        : c.remote_ip
          ? `<a class="link mono" data-ip="${esc(c.remote_ip)}" title="點一下分析這個 IP">${esc(endpoint(c.remote_ip, c.remote_port))}</a>`
          : '—';
      const geo = c.geo ? `${esc(c.geo.country ?? '')}<div class="muted small">${c.geo.asn ? `AS${esc(c.geo.asn)} ` : ''}${esc(c.geo.org ?? '')}</div>` : '<span class="muted">—</span>';
      return `<tr>
        <td><span class="chip ${esc(c.verdict.level)}" title="${esc(VERDICT_HINT[c.verdict.level] ?? '')}">${VERDICT[c.verdict.level] ?? esc(c.verdict.level)}</span></td>
        <td><span class="chip dir" title="${esc(DIR_HINT[c.direction] ?? '')}">${DIRECTION[c.direction] ?? esc(c.direction)}</span><div class="muted small nw" title="${esc(STATE_HINT[c.state] ?? '')}">${esc(c.proto)} · ${esc(c.state)}</div></td>
        <td>${remote}</td>
        <td class="small mono" style="text-align:right">${n}</td>
        <td class="small">${geo}</td>
        <td class="small"><b>${esc(c.process?.name ?? '—')}</b>${c.process?.pid != null ? `<div class="muted">pid ${esc(c.process.pid)}</div>` : ''}</td>
        <td>${(c.verdict.reasons ?? []).map(reasonHtml).join('') || '<span class="muted">—</span>'}</td>
      </tr>`;
    })
    .join('')}</tbody></table>`;
}

const connState = {
  verdict: new Set(['dangerous', 'suspicious']),
  direction: new Set(),
  proto: new Set(),
  state: new Set(),
  reason: new Set(),
  process: '',
  country: '',
  port: '',
  publicOnly: false,
  hideLoopback: false,
  q: '',
  more: false,
  sort: { key: 'verdict', dir: 1 },
  auto: false,
  timer: null,
};

const REASON_KIND = { intel: '情資', behavior: '行為', none: '沒有理由' };
const REASON_HINT = { intel: '有威脅情資清單列名', behavior: 'asa 自己的行為判斷（例如週期性連線、新目的地）', none: '沒有任何可疑理由' };
const VERDICT_HINT = { dangerous: '有可信的威脅情資列名，或多個可疑行為', suspicious: '有可疑的地方，值得看一下', unknown: '沒有情資列名、也沒有可疑行為，只是不認識', safe: '已知良好的服務、私有網路或本機' };
const DIR_HINT = { outbound: '這台主動連出去的', inbound: '別台電腦連進這台的', listening: '這台開著 port，等別人連進來', local: '這台電腦裡的程式彼此連線（127.0.0.1 這類）' };
const PROTO_HINT = { tcp: 'TCP：要先建立連線的協定（網頁、遠端桌面…）', udp: 'UDP：不必建立連線的協定（DNS、視訊、遊戲…），沒有連線狀態' };
const STATE_HINT = {
  ESTABLISHED: '連線中，正在傳資料',
  LISTEN: '開著 port，等別人連進來',
  BOUND: '已佔用 port（UDP 沒有連線狀態，綁好就是這個）',
  TIME_WAIT: '剛結束的連線，系統稍等一下再回收（正常）',
  CLOSE_WAIT: '對方已經關閉、這台的程式還沒關（大量出現可能是程式沒處理好）',
  FIN_WAIT1: '這台要求結束連線，等對方回應',
  FIN_WAIT2: '這台要求結束連線，等對方也關閉',
  SYN_SENT: '正在嘗試連出去（大量出現可能是連不上，或在掃描）',
  SYN_RECEIVED: '有人正在連進來，還沒連好',
  SYN_RECV: '有人正在連進來，還沒連好',
  LAST_ACK: '連線結束中，等最後確認',
  CLOSING: '雙方同時在結束連線',
  CLOSED: '已關閉',
};

/** 私有、保留、本機位址（不算公網）。 */
function isPublicIp(ip) {
  if (!ip) return false;
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    if (l.startsWith('::ffff:')) return isPublicIp(l.slice(7));
    return !(l === '::' || l === '::1' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff'));
  }
  const [a, b] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
}

function isLoopback(c) {
  const ip = c.remote_ip ?? c.local_ip ?? '';
  return ip.startsWith('127.') || ip === '::1' || ip.startsWith('::ffff:127.');
}

/** 「更多篩選」裡用了幾個條件（按鈕上的數字）。 */
function advCount() {
  return connState.proto.size + connState.state.size + connState.reason.size +
    [connState.process, connState.country, connState.port, connState.publicOnly, connState.hideLoopback].filter(Boolean).length;
}

function moreLabel() {
  const n = advCount();
  return `更多篩選${n ? ` <span class="badge">${n}</span>` : ''} ${connState.more ? '▴' : '▾'}`;
}

async function pageConnections() {
  $main.innerHTML = `
    <div class="head">
      <div><h1>連線</h1><p class="sub">這台電腦目前的連線，依威脅情資與異常行為判定；點 IP 看詳細分析，點表頭排序。</p></div>
      <div class="row">
        <label class="small row" title="每 10 秒重新讀一次這台的連線"><input type="checkbox" id="auto" ${connState.auto ? 'checked' : ''}/> 每 10 秒更新</label>
        <button class="btn" id="refresh">重新整理</button>
        <button class="btn primary" id="ask">請 AI 分析可疑連線</button>
      </div>
    </div>
    <div class="card">
      <form class="filters search-row" id="f-search" autocomplete="off">
        <input type="search" id="q" data-search placeholder="IP、程式或組織（輸入 IP 按查詢可直接分析）" value="${esc(connState.q)}" aria-label="搜尋連線"/>
        <button class="btn primary" type="submit" title="套用篩選並重新讀取連線；輸入的是 IP 時另外打開 IP 分析（快速鍵 Ctrl+F）">查詢</button>
        <button class="btn" type="button" id="f-clear">清除篩選</button>
        <button class="btn" type="button" id="f-more" aria-expanded="${connState.more}" aria-controls="f-adv">${moreLabel()}</button>
      </form>
      <div class="filters" id="f-verdict"></div>
      <div class="filters" id="f-dir"></div>
      <div id="f-adv" class="adv" ${connState.more ? '' : 'hidden'}>
        <div class="filters" id="f-proto"></div>
        <div class="filters" id="f-state"></div>
        <div class="filters" id="f-reason"></div>
        <div class="filters">
          <label class="small">程式 <select id="f-process"></select></label>
          <label class="small">國家 <select id="f-country"></select></label>
          <label class="small">port <input type="text" id="f-port" inputmode="numeric" placeholder="例：443" value="${esc(connState.port)}" style="width:80px"/></label>
          <label class="small row" title="只看連到網際網路上的位址（排除區網、本機、保留位址）"><input type="checkbox" id="f-public" ${connState.publicOnly ? 'checked' : ''}/> 只看公網位址</label>
          <label class="small row" title="隱藏 127.0.0.1、::1 這類程式在自己電腦內部的連線"><input type="checkbox" id="f-loop" ${connState.hideLoopback ? 'checked' : ''}/> 隱藏本機迴路</label>
        </div>
      </div>
    </div>
    <div class="card">
      <p class="small muted" id="count" style="margin:0 0 6px">載入中…</p>
      <div id="tbl" class="tbl-wrap"></div>
    </div>`;
  const $ = (id) => document.getElementById(id);
  $('refresh').onclick = () => loadConns();
  $('ask').onclick = () => goAi('connections', '');
  $('f-search').onsubmit = (e) => {
    e.preventDefault();
    connState.q = $('q').value;
    const v = connState.q.trim();
    if (isIpLike(v)) showIp(v);
    loadConns();
  };
  $('q').oninput = (e) => { connState.q = e.target.value; renderConns(); };
  $('f-port').oninput = (e) => { connState.port = e.target.value.replace(/\D/g, ''); renderConns(); };
  $('f-public').onchange = (e) => { connState.publicOnly = e.target.checked; renderConns(); };
  $('f-loop').onchange = (e) => { connState.hideLoopback = e.target.checked; renderConns(); };
  $('f-process').onchange = (e) => { connState.process = e.target.value; renderConns(); };
  $('f-country').onchange = (e) => { connState.country = e.target.value; renderConns(); };
  $('f-more').onclick = () => {
    connState.more = !connState.more;
    $('f-adv').hidden = !connState.more;
    $('f-more').setAttribute('aria-expanded', String(connState.more));
    $('f-more').innerHTML = moreLabel();
  };
  $('f-clear').onclick = () => {
    for (const k of ['verdict', 'direction', 'proto', 'state', 'reason']) connState[k].clear();
    Object.assign(connState, { process: '', country: '', port: '', publicOnly: false, hideLoopback: false, q: '' });
    pageConnections();
  };
  $('tbl').addEventListener('click', (e) => {
    const act = e.target.closest('[data-act]');
    if (act?.dataset.act === 'all') {
      connState.verdict.clear();
      renderConns();
      return;
    }
    if (act?.dataset.act === 'clear') {
      $('f-clear').click();
      return;
    }
    const th = e.target.closest('th[data-sort]');
    if (!th) return;
    const key = th.dataset.sort;
    connState.sort = connState.sort.key === key ? { key, dir: -connState.sort.dir } : { key, dir: key === 'n' ? -1 : 1 };
    renderConns();
  });
  $('auto').onchange = (e) => { connState.auto = e.target.checked; setAuto(); };
  setAuto();
  await loadConns();
}

function setAuto() {
  clearInterval(connState.timer);
  if (connState.auto) connState.timer = setInterval(() => location.hash === '#connections' && loadConns(), 10000);
}

let lastConns = [];
async function loadConns() {
  try {
    lastConns = (await invoke('connections')).connections;
    fillSelects();
    renderConns();
  } catch (e) {
    const t = document.getElementById('tbl');
    if (t) t.innerHTML = `<p class="small" style="color:var(--danger)">${esc(e)}</p>`;
  }
}

/** 程式、國家下拉：依出現次數排序（資料更新時才重建，選到的值保留）。 */
function fillSelects() {
  const fill = (id, all, values, cur) => {
    const el = document.getElementById(id);
    if (!el) return;
    const counts = new Map();
    for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
    const opts = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    if (cur && !counts.has(cur)) opts.unshift([cur, 0]);
    el.innerHTML = `<option value="">${all}</option>` + opts.map(([v, n]) => `<option value="${esc(v)}" ${v === cur ? 'selected' : ''}>${esc(v)}（${n}）</option>`).join('');
  };
  fill('f-process', '全部程式', lastConns.map((c) => c.process?.name), connState.process);
  fill('f-country', '全部國家', lastConns.map((c) => c.geo?.country), connState.country);
}

function renderConns() {
  const fv = document.getElementById('f-verdict');
  if (!fv) return;
  const chipRow = (el, label, set, entries, valueOf, hints = {}) => {
    const counts = new Map();
    for (const c of lastConns) {
      const v = valueOf(c);
      counts.set(v, (counts.get(v) ?? 0) + 1);
    }
    document.getElementById(el).innerHTML =
      `<span class="muted small filter-label">${label}</span>` +
      entries(counts)
        .map(([v, l]) => `<button type="button" class="fchip ${set.has(v) ? 'on' : ''}" data-set="${el}" data-v="${esc(v)}" aria-pressed="${set.has(v)}" ${hints[v] ? `title="${esc(hints[v])}"` : ''}>${esc(l)}<span class="n">${counts.get(v) ?? 0}</span></button>`)
        .join('');
  };
  const SETS = { 'f-verdict': connState.verdict, 'f-dir': connState.direction, 'f-proto': connState.proto, 'f-state': connState.state, 'f-reason': connState.reason };
  chipRow('f-verdict', '判定', connState.verdict, () => Object.entries(VERDICT), (c) => c.verdict.level, VERDICT_HINT);
  chipRow('f-dir', '方向', connState.direction, () => Object.entries(DIRECTION), (c) => c.direction, DIR_HINT);
  chipRow('f-proto', '協定', connState.proto, (m) => [...m.keys()].sort().map((v) => [v, v.toUpperCase()]), (c) => String(c.proto ?? '').toLowerCase(), PROTO_HINT);
  chipRow('f-state', '狀態', connState.state, (m) => [...m.entries()].sort((a, b) => b[1] - a[1]).map(([v]) => [v, v || '—']), (c) => c.state ?? '', STATE_HINT);
  chipRow('f-reason', '理由', connState.reason, () => Object.entries(REASON_KIND), reasonKind, REASON_HINT);
  for (const b of document.querySelectorAll('.fchip[data-set]')) {
    b.onclick = () => {
      const set = SETS[b.dataset.set];
      set.has(b.dataset.v) ? set.delete(b.dataset.v) : set.add(b.dataset.v);
      renderConns();
    };
  }
  const more = document.getElementById('f-more');
  if (more) more.innerHTML = moreLabel();
  const q = connState.q.trim().toLowerCase();
  const port = connState.port ? Number(connState.port) : null;
  const rows = lastConns.filter(
    (c) =>
      (!connState.verdict.size || connState.verdict.has(c.verdict.level)) &&
      (!connState.direction.size || connState.direction.has(c.direction)) &&
      (!connState.proto.size || connState.proto.has(String(c.proto ?? '').toLowerCase())) &&
      (!connState.state.size || connState.state.has(c.state ?? '')) &&
      (!connState.reason.size || connState.reason.has(reasonKind(c))) &&
      (!connState.process || c.process?.name === connState.process) &&
      (!connState.country || c.geo?.country === connState.country) &&
      (port === null || c.remote_port === port || c.local_port === port) &&
      (!connState.publicOnly || isPublicIp(c.remote_ip)) &&
      (!connState.hideLoopback || !isLoopback(c)) &&
      (!q || [c.remote_ip, c.local_ip, c.process?.name, c.geo?.org, c.geo?.country].some((x) => String(x ?? '').toLowerCase().includes(q))),
  );
  const groups = sortGroups(groupConns(rows));
  document.getElementById('count').textContent = `${rows.length} 條連線（合併成 ${groups.length} 列）· 這台目前共 ${lastConns.length} 條`;
  let empty = '';
  if (!groups.length) {
    const onlyRisky = connState.verdict.size && [...connState.verdict].every((v) => v === 'dangerous' || v === 'suspicious');
    const noRisky = !lastConns.some((c) => c.verdict.level === 'dangerous' || c.verdict.level === 'suspicious');
    empty = onlyRisky && noRisky
      ? `<div class="empty"><b>目前沒有危險或可疑的連線</b><p class="small">情資和行為判斷都沒有發現問題。</p><button class="btn" data-act="all">看全部連線</button></div>`
      : `<div class="empty">沒有符合的連線<p><button class="btn" data-act="clear">清除篩選</button></p></div>`;
  }
  document.getElementById('tbl').innerHTML = groups.length ? connTable(groups) : empty;
}

async function showIp(ip) {
  const body = openDrawer('IP 分析', `<p class="mono big">${esc(ip)}</p><p class="muted small"><span class="spin"></span> 查詢中…</p>`);
  try {
    const conns = lastConns.length ? lastConns : await invoke('connections').then((x) => (lastConns = x.connections)).catch(() => []);
    const r = await invoke('lookup_ip', { ip });
    if (!body.isConnected) return;
    const mine = conns.filter((c) => c.remote_ip === ip);
    const level = mine.map((c) => c.verdict.level).sort((a, b) => (VERDICT_RANK[a] ?? 9) - (VERDICT_RANK[b] ?? 9))[0];
    body.innerHTML = `
      <p class="mono big">${esc(ip)} ${level ? `<span class="chip ${esc(level)}" title="${esc(VERDICT_HINT[level] ?? '')}">${VERDICT[level] ?? esc(level)}</span>` : ''}</p>
      <div class="kv">
        <div>國家</div><div>${esc(r.geo?.country ?? '—')}</div>
        <div>組織／ASN</div><div>${esc(r.geo?.org ?? '—')}${r.geo?.asn ? ` (AS${esc(r.geo.asn)})` : ''}</div>
        <div>位址類型</div><div>${esc(r.class)}</div>
      </div>
      <h3>情資命中</h3>
      ${r.hits.length ? r.hits.map((h) => `<div class="small" style="margin-bottom:4px"><a class="link" data-url="${esc(h.source_url)}">${esc(h.vendor)} · ${esc(h.name)}</a> <span class="muted">信心 ${esc(h.confidence)}% · ${esc(h.license ?? '')}</span></div>`).join('') : '<p class="muted small">沒有任何情資來源列名（若被判可疑，是行為判斷）。</p>'}
      <h3>這台哪些程式連它</h3>
      ${mine.length ? [...new Set(mine.map((c) => `${c.process?.name ?? '—'}（${c.state}）`))].map((x) => `<div class="small">${esc(x)}</div>`).join('') : '<p class="muted small">目前沒有連線。</p>'}
      <div class="row" style="margin-top:16px">
        <button class="btn primary" id="ip-ai">請 AI 分析這個 IP</button>
        <button class="btn" data-url="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}">VirusTotal</button>
        <button class="btn" data-url="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}">AbuseIPDB</button>
      </div>
      <p class="muted small" style="margin-top:8px">外部網站只是連結，按了才會在瀏覽器開啟。</p>`;
    document.getElementById('ip-ai').onclick = () => goAi('free', `分析這個 IP：${ip}。用 lookup_ip 查情資與國家／ASN，用 list_connections 看本機哪些程式連它；判斷它大概是什麼服務、被判可疑的理由是情資還是行為判斷、是不是誤報，最後給出建議。`);
  } catch (e) {
    if (body.isConnected) body.innerHTML = `<p class="small" style="color:var(--danger)">${esc(e)}</p>`;
  }
}

// ---------------- 掃描結果 ----------------
const ALLOW_KIND = {
  finding: '單一掃描項目',
  ip: 'IP',
  cidr: '網段',
  process_path: '程式路徑',
  domain: '網域',
  rule: '規則',
};

function findingRow(f, allowEntries) {
  const entry = f.suppressed_by ? allowEntries.find((item) => item.id === f.suppressed_by) : null;
  const excluded = Boolean(f.suppressed_by);
  const note = entry?.note?.trim();
  return `<tr class="finding-row${excluded ? ' excluded-row' : ''}" data-finding-row data-excluded="${excluded}"${excluded ? ' hidden' : ''}>
    <td class="finding-severity"><span class="chip ${esc(f.severity)}">${SEVERITY[f.severity] ?? esc(f.severity)}</span></td>
    <td><details><summary><b>${esc(f.title)}</b>${excluded ? ' <span class="chip ok">已排除</span>' : ''}</summary>
      <div class="finding-body">
        <p class="small">${esc(f.detail)}</p>
        ${f.recommendation ? `<p class="small"><b>建議：</b>${esc(f.recommendation)}</p>` : ''}
        ${(f.intel_hits ?? []).map((h) => `<span class="reason intel" data-url="${esc(h.source_url)}"><span class="k">情資</span>${esc(h.vendor)} ${esc(h.confidence)}%</span>`).join('')}
        ${excluded ? `<div class="allow-state">
          <div><b>白名單排除中</b>${note ? `<span class="allow-note">${esc(note)}</span>` : '<span class="muted">沒有備註</span>'}</div>
          ${entry ? `<button class="btn compact" data-unexclude="${esc(entry.id)}" data-unexclude-kind="${esc(entry.kind)}">取消排除</button>` : ''}
        </div>` : `<div class="finding-actions">
          <button class="btn compact" data-exclude="${esc(f.id)}">加入白名單排除</button>
          <span class="muted small">只排除此項，不影響同類型的其他問題。</span>
        </div>
        <form class="allow-form" data-exclude-form="${esc(f.id)}" hidden>
          <label for="allow-note-${esc(f.id)}"><b>排除原因</b><span class="muted">（必填，方便日後稽核）</span></label>
          <input id="allow-note-${esc(f.id)}" type="text" maxlength="500" required data-allow-note placeholder="例如：公司核准的端點防護服務，IT-1234" autocomplete="off">
          <div class="row"><button class="btn primary compact" type="submit">確認排除</button><button class="btn compact" type="button" data-cancel-exclude>取消</button></div>
        </form>`}
      </div>
    </details></td>
    <td class="small muted finding-category">${esc(f.scanner)}<div class="mono">${esc(f.rule)}</div></td>
  </tr>`;
}

function allowlistPanel(entries) {
  return `<details class="card allowlist-panel">
    <summary><b>掃描排除管理</b><span class="badge">${entries.length}</span><span class="muted small">查看備註或取消排除</span></summary>
    <div class="tbl-wrap allowlist-table">${entries.length ? `<table><thead><tr><th>範圍</th><th>項目</th><th>備註</th><th>加入時間</th><th></th></tr></thead><tbody>${entries.map((entry) => `<tr>
      <td><span class="chip neutral">${esc(ALLOW_KIND[entry.kind] ?? entry.kind)}</span></td>
      <td class="mono allow-value">${esc(entry.value)}</td>
      <td class="small">${entry.note ? esc(entry.note) : '<span class="muted">沒有備註</span>'}</td>
      <td class="small muted nw">${ago(entry.added_at)}</td>
      <td><button class="btn compact" data-unexclude="${esc(entry.id)}" data-unexclude-kind="${esc(entry.kind)}">取消</button></td>
    </tr>`).join('')}</tbody></table>` : '<div class="empty">目前沒有掃描排除。</div>'}</div>
  </details>`;
}

async function pageFindings() {
  $main.innerHTML = `<h1>掃描結果</h1><p class="sub">載入中…</p>`;
  const [r, allowlist] = await Promise.all([
    invoke('latest_report'),
    invoke('allowlist_list').catch(() => ({ entries: [] })),
  ]);
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const fs = (r?.findings ?? []).slice().sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const allowEntries = allowlist?.entries ?? [];
  const active = fs.filter((f) => !f.suppressed_by);
  const excluded = fs.filter((f) => f.suppressed_by);
  const findingAllowEntries = allowEntries.filter((entry) => entry.kind === 'finding' || fs.some((f) => f.suppressed_by === entry.id));
  $main.innerHTML = `
    <div class="head">
      <div><h1>掃描結果</h1><p class="sub">${r ? `最後掃描 ${ago(r.finished_at)}，${active.length} 筆待處理${excluded.length ? `，${excluded.length} 筆已排除` : ''}` : '還沒有掃描報告'}</p></div>
      <div class="row"><button class="btn primary" id="scan">立即掃描</button><button class="btn" id="ask">請 AI 解讀這份報告</button></div>
    </div>
    ${excluded.length ? `<label class="check-toggle"><input type="checkbox" id="show-excluded"> 顯示已排除項目 <span class="badge">${excluded.length}</span></label>` : ''}
    <div class="card findings-card">${fs.length ? `<div class="tbl-wrap"><table><thead><tr><th>嚴重度</th><th>問題</th><th>類別</th></tr></thead><tbody>${fs.map((f) => findingRow(f, allowEntries)).join('')}</tbody></table></div>
      ${active.length ? '' : `<div class="empty" id="active-findings-empty"><b>目前沒有待處理問題</b>${excluded.length ? '<p class="small">已排除的項目可用上方開關查看。</p>' : ''}</div>`}` : '<div class="empty">沒有問題，或還沒掃描過。</div>'}</div>
    ${allowlistPanel(findingAllowEntries)}`;
  document.getElementById('scan').onclick = () => scanNow();
  document.getElementById('ask').onclick = () => goAi('report', '');
  const showExcluded = document.getElementById('show-excluded');
  if (showExcluded) {
    showExcluded.onchange = () => {
      document.querySelectorAll('[data-finding-row][data-excluded="true"]').forEach((row) => (row.hidden = !showExcluded.checked));
      const empty = document.getElementById('active-findings-empty');
      if (empty) empty.hidden = showExcluded.checked;
    };
  }
  document.querySelectorAll('[data-exclude]').forEach((button) => {
    button.onclick = () => {
      const form = document.querySelector(`[data-exclude-form="${CSS.escape(button.dataset.exclude)}"]`);
      button.hidden = true;
      form.hidden = false;
      form.querySelector('[data-allow-note]').focus();
    };
  });
  document.querySelectorAll('[data-cancel-exclude]').forEach((button) => {
    button.onclick = () => {
      const form = button.closest('form');
      form.hidden = true;
      const openButton = document.querySelector(`[data-exclude="${CSS.escape(form.dataset.excludeForm)}"]`);
      if (openButton) openButton.hidden = false;
    };
  });
  document.querySelectorAll('[data-exclude-form]').forEach((form) => {
    form.onsubmit = async (event) => {
      event.preventDefault();
      const input = form.querySelector('[data-allow-note]');
      if (!input.reportValidity()) return;
      const buttons = form.querySelectorAll('button');
      buttons.forEach((button) => (button.disabled = true));
      try {
        await invoke('allowlist_add_finding', { findingId: form.dataset.excludeForm, note: input.value });
        toast('已加入白名單；這筆問題不再計分或告警。');
        await pageFindings();
      } catch (e) {
        toast(`無法加入白名單：${e}`);
        buttons.forEach((button) => (button.disabled = false));
      }
    };
  });
  document.querySelectorAll('[data-unexclude]').forEach((button) => {
    button.onclick = async () => {
      if (button.dataset.unexcludeKind !== 'finding' && !window.confirm('這是共用白名單，取消後可能會讓多筆掃描問題恢復。確定要取消？')) return;
      button.disabled = true;
      try {
        await invoke('allowlist_remove', { entryId: button.dataset.unexclude });
        toast('已取消白名單排除。');
        await pageFindings();
      } catch (e) {
        toast(`無法取消排除：${e}`);
        button.disabled = false;
      }
    };
  });
}

// ---------------- 威脅情資 ----------------
async function pageIntel() {
  $main.innerHTML = `<h1>威脅情資</h1><p class="sub">載入中…</p>`;
  const { feeds } = await invoke('intel_feeds');
  $main.innerHTML = `
    <div class="head">
      <div><h1>威脅情資</h1><p class="sub">判定連線用的公開情資清單。已註冊 Hub 時優先從 Hub 下載，Hub 沒有才直接找廠商。</p></div>
      <div class="row"><button class="btn" id="upd">更新過期的</button><button class="btn primary" id="force">全部重新下載</button></div>
    </div>
    <div class="card" id="intel-keys"><h2>線上查詢金鑰（選用）</h2><p class="small muted">讀取中…</p></div>
    <div class="card"><table><thead><tr><th>來源</th><th>種類</th><th>筆數</th><th>最後更新</th><th>授權</th></tr></thead><tbody>${feeds
      .map((f) => `<tr>
        <td><a class="link" data-url="${esc(f.source_url)}"><b>${esc(f.vendor)}</b> ${esc(f.name)}</a>${
          f.license_blocked
            ? ' <a class="chip neutral" href="#settings/intel" title="這個來源只准個人或非營利使用；這台電腦選的是公司／商業用途，所以沒有使用。到設定頁的「情資來源授權」可以改。">未使用（只限非商用）</a>'
            : f.enabled
              ? ''
              : ' <span class="chip neutral">已停用</span>'
        }</td>
        <td class="small">${esc(f.kind)}</td>
        <td class="small mono">${f.entries ? Number(f.entries).toLocaleString() : '—'}</td>
        <td class="small">${ago(f.fetched_at)}${f.from_hub ? ' <span class="chip dir">Hub</span>' : ''}${f.status === 'error' ? ` <span class="chip medium" title="${esc(f.error)}">失敗</span>` : ''}${f.status === 'never' ? ' <span class="chip neutral">未下載</span>' : ''}</td>
        <td class="small muted">${esc(f.license)}${f.commercial_ok ? '' : ' <span class="chip neutral" title="只准個人或非營利使用，公司或營利用途要另外向廠商買授權。">非商用</span>'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  renderIntelKeys(document.getElementById('intel-keys'));
  document.getElementById('upd').onclick = () => updateIntel(false);
  document.getElementById('force').onclick = () => updateIntel(true);
}

// ---------------- DNS ----------------
const dnsState = { minutes: 60, suspicious: false, q: '' };
const DNS_SOURCE = {
  etw: ['Windows DNS 事件', '背景服務以系統管理員執行時，即時收 Windows 的 DNS 查詢事件，看得到是哪個程式查的。'],
  eventlog: ['Windows DNS 事件紀錄', '讀 Windows 的 DNS Client 事件紀錄，看得到是哪個程式查的。'],
  cache: ['DNS 快取快照', '沒有系統管理員權限時，每 30 秒讀一次 DNS 快取；看不到是哪個程式查的。'],
  packet: ['監聽 DNS 封包', '直接看網路卡上的 DNS 回應（需要 root）。'],
  resolved: ['systemd-resolved', '讀 Linux 的 systemd-resolved 查詢紀錄。'],
};
const DNS_HINT = {
  nx: 'NXDOMAIN＝查無此網域。偶爾出現很正常；同一個程式短時間大量出現，常是用亂數網域找控制伺服器的惡意程式。',
  domains: '依「可註冊網域」計算：a.b.example.co.uk 算成 example.co.uk，同一家的子網域合成一個。',
  suspicious: '威脅情資列名的網域、黑名單上的網域、像亂數產生的網域、少見的頂級網域，或加密 DNS 端點（程式自己走加密 DNS 會繞過公司的 DNS）。',
  protect: '公司的防護 DNS 會擋掉威脅情資列名的網域；把這台的 DNS 指過去後，防護 DNS 連續 3 分鐘查不到時背景服務會自動改回原本的 DNS。',
  enabled: '即時記錄這台查了哪些網域、是哪個程式查的，可疑的會變成掃描結果。關掉就不記錄、也不做 DNS 告警，「DNS」頁會顯示未啟用。',
  upload: 'DNS 紀錄等於上網紀錄。「全部」＝每分鐘把紀錄送到公司的 Hub；「只傳告警」＝只送可疑的；「不傳」＝只留在這台。',
  verify: '拿 3 個常見網域的答案跟 Cloudflare 的加密 DNS 比對，抓 DNS 被竄改。開了會把這 3 個網域送給 Cloudflare。',
  server: '讓這台電腦當整個區網的防護 DNS（擋威脅情資列名的網域、上游走加密 DNS）。要背景服務在跑；其他裝置的 DNS 指到這台的區網 IP 才會用到。',
  blocklist: '黑名單上的網域（含子網域）：這台查到就告警，用防護 DNS 的電腦會直接被擋。白名單上的網域（含子網域）：這台不告警、這台跑的防護 DNS 也不擋（情資誤判、公司內部系統用）。Hub 的黑白名單是公司統一管理的，在 Hub「設定與金鑰 → 防護 DNS」修改。',
};

async function dnsDo(fn, okText) {
  try {
    const r = await fn();
    if (okText) toast(okText);
    return r;
  } catch (e) {
    toast(String(e), 6000);
    return null;
  }
}

/** 設定頁 DNS 區塊的黑白名單（這台的可以移除；Hub 的只能看）。 */
function dnsListsHtml(d) {
  const local = d.blocklist?.local ?? [];
  const hub = d.blocklist?.hub ?? [];
  const allowLocal = d.allowlist?.local ?? [];
  const allowHub = d.allowlist?.hub ?? [];
  const rows = (items) => `<div class="tbl-wrap"><table style="margin-top:4px"><tbody>${items.join('')}</tbody></table></div>`;
  const hubCell = '<td class="small muted nw" title="公司統一管理，在 Hub「設定與金鑰 → 防護 DNS」修改">Hub</td><td></td>';
  return `
    <h3 class="sub-h" title="${esc(DNS_HINT.blocklist)}">黑白名單 <span class="muted">(?)</span></h3>
    <div class="row"><input type="text" id="dns-bl-add" placeholder="網域或網址，例：bad.example" style="width:260px"/><button class="btn primary" id="dns-bl-btn">加入黑名單</button><button class="btn" id="dns-al-btn">加入白名單</button></div>
    <div class="usage-grid" style="margin-top:10px">
      <div><div class="small"><b>黑名單</b> <span class="muted">擋下、告警</span></div>
        ${local.length || hub.length ? rows([
          ...local.map((e) => `<tr><td class="mono small">${esc(e.domain)}${e.note ? `<div class="small muted">${esc(e.note)}</div>` : ''}</td><td class="small muted nw">這台</td><td class="nw"><button class="btn" data-unblock="${esc(e.domain)}" title="從這台的黑名單移除" aria-label="移除 ${esc(e.domain)}">✕</button></td></tr>`),
          ...hub.map((x) => `<tr><td class="mono small">${esc(x)}</td>${hubCell}</tr>`),
        ]) : '<p class="small muted">還沒有。也可以在「DNS」頁的查詢紀錄按「封鎖」。</p>'}</div>
      <div><div class="small"><b>白名單</b> <span class="muted">不擋、不告警</span></div>
        ${allowLocal.length || allowHub.length ? rows([
          ...allowLocal.map((x) => `<tr><td class="mono small">${esc(x)}</td><td class="small muted nw">這台</td><td class="nw"><button class="btn" data-unallow="${esc(x)}" title="從這台的白名單移除" aria-label="移除 ${esc(x)}">✕</button></td></tr>`),
          ...allowHub.map((x) => `<tr><td class="mono small">${esc(x)}</td>${hubCell}</tr>`),
        ]) : '<p class="small muted">還沒有。情資誤判時可以在「DNS」頁按「放行」。</p>'}</div>
    </div>`;
}

/** 黑白名單的增刪（DNS 頁、設定頁、網域分析共用），做完呼叫 after。 */
async function dnsListChange(cmd, domains, after) {
  const r = await dnsDo(() => invoke(cmd, cmd === 'dns_block' || cmd === 'dns_allow' ? { domains, note: null } : { domains }));
  if (!r) return;
  const list = (x) => x.join('、');
  if (cmd === 'dns_block') toast(r.added.length ? `已加入黑名單：${list(r.added)}（含子網域）` : r.invalid.length ? `不是合法的網域：${list(r.invalid)}` : '已經在黑名單上了', 5000);
  if (cmd === 'dns_allow') toast(r.added.length ? `已加入白名單：${list(r.added)}（含子網域）` : r.invalid.length ? `不是合法的網域：${list(r.invalid)}` : '已經在白名單上了', 5000);
  if (cmd === 'dns_unblock') toast(r.removed.length ? `已從黑名單移除：${list(r.removed)}` : '這台的黑名單上沒有它');
  if (cmd === 'dns_unallow') toast(r.removed.length ? `已從白名單移除：${list(r.removed)}` : '這台的白名單上沒有它');
  after?.();
}

/** 設定頁的「DNS」區塊：監看開關、上傳、比對答案、用公司的防護 DNS、這台當防護 DNS、黑白名單。 */
async function renderDnsSettings(el) {
  if (!el) return;
  let d;
  try {
    d = await invoke('dns_settings');
  } catch (e) {
    el.innerHTML = `<h2>DNS</h2><p class="small" style="color:var(--danger)">${esc(e)}</p>`;
    return;
  }
  const sel = (v) => (d.upload === v ? 'selected' : '');
  const usedHub = d.use_hub
    ? `<p class="small">目前用的是公司的防護 DNS（<span class="mono">${esc(d.use_hub.servers.join('、'))}</span>，從 ${ago(d.use_hub.applied_at)} 起）。</p><button class="btn" id="dns-restore">改回原本的 DNS</button>`
    : `<p class="small muted">${d.hub_protect?.resolver_ips?.length ? `公司的防護 DNS：<span class="mono">${esc(d.hub_protect.resolver_ips.join('、'))}</span>` : '還沒有公司的防護 DNS 位址（Hub「設定與金鑰 → 防護 DNS」的「裝置要用的 DNS 位址」），也可以自己填。'}</p>
       <div class="row"><input type="text" id="dns-hub-ip" placeholder="${esc(d.hub_protect?.resolver_ips?.join(',') || '例：192.168.1.5')}" style="width:200px"/><button class="btn primary" id="dns-use-hub">把這台的 DNS 指過去</button></div>`;
  el.innerHTML = `<h2>DNS</h2>
    <label class="row" title="${esc(DNS_HINT.enabled)}"><input type="checkbox" id="dns-set-enabled" ${d.enabled ? 'checked' : ''}/> <b>啟用 DNS 監看</b> <span class="small muted">(?)</span></label>
    <p class="small muted" style="margin:4px 0 0 24px">${d.enabled ? '記錄這台查了哪些網域、是哪個程式查的；可疑的會告警，紀錄在「DNS」頁。' : '目前沒有記錄，「DNS」頁會顯示未啟用。'}</p>
    <fieldset class="plain" ${d.enabled ? '' : 'disabled'} style="margin:8px 0 0 24px">
      <label class="small row" title="${esc(DNS_HINT.upload)}">上傳到公司的 Hub <span class="muted">(?)</span>
        <select id="dns-set-upload"><option value="all" ${sel('all')}>全部</option><option value="alerts" ${sel('alerts')}>只傳告警</option><option value="off" ${sel('off')}>不傳</option></select></label>
      <label class="row small" style="margin-top:8px" title="${esc(DNS_HINT.verify)}"><input type="checkbox" id="dns-set-verify" ${d.verify_answers ? 'checked' : ''}/> 比對 DNS 答案（抓竄改） <span class="muted">(?)</span></label>
    </fieldset>
    <div class="sub-section">
      <h3 class="sub-h" style="margin-top:0" title="${esc(DNS_HINT.protect)}">這台用公司的防護 DNS <span class="muted">(?)</span></h3>
      ${usedHub}
      <p class="small muted" style="margin:6px 0 0">改系統 DNS 需要系統管理員權限，會跳出確認視窗。</p>
    </div>
    <div class="sub-section">
      <label class="row small" title="${esc(DNS_HINT.server)}"><input type="checkbox" id="dns-set-server" ${d.dns_server ? 'checked' : ''}/> <b>這台當防護 DNS</b> <span class="muted">(?)</span></label>
      <div class="row small" style="margin:6px 0 0 24px" id="dns-listen-row" ${d.dns_server ? '' : 'hidden'}>監聽位址 <input type="text" id="dns-set-listen" value="${esc(d.dns_server_listen)}" placeholder="空白＝全部網卡的 53 port" style="width:220px"/><button class="btn" id="dns-save-listen">儲存</button></div>
    </div>
    <div class="sub-section">${dnsListsHtml(d)}</div>`;
  const $ = (id) => document.getElementById(id);
  const again = () => renderDnsSettings(el);
  const set = async (key, value, ok) => {
    const r = await dnsDo(() => invoke('dns_set', { key, value: String(value) }), ok);
    again();
    return r;
  };
  $('dns-set-enabled').onchange = (e) => set('dns.enabled', e.target.checked, e.target.checked ? '已啟用 DNS 監看（背景服務下一輪開始記錄）' : '已停用 DNS 監看');
  $('dns-set-upload').onchange = (e) => set('dns.upload', e.target.value, '已儲存');
  $('dns-set-verify').onchange = (e) => set('dns.verify_answers', e.target.checked, '已儲存');
  $('dns-set-server').onchange = (e) => set('dns.server.enabled', e.target.checked, e.target.checked ? '背景服務 1 分鐘內會帶起防護 DNS' : '背景服務 1 分鐘內會停掉防護 DNS');
  $('dns-save-listen').onclick = () => set('dns.server.listen', $('dns-set-listen').value, '已儲存監聽位址');
  if ($('dns-use-hub')) {
    $('dns-use-hub').onclick = async () => {
      const ip = $('dns-hub-ip').value.trim();
      if (!window.confirm(`把這台的系統 DNS 改成${ip ? ` ${ip}` : '公司的防護 DNS'}？\n\n原本的設定會存起來，可以按「改回原本的 DNS」；防護 DNS 連不上時背景服務也會自動改回。`)) return;
      const r = await dnsDo(() => invoke('dns_use_hub', { server: ip || null }));
      if (r) { toast((r.lines || []).join('\n') || '已改好', 6000); again(); }
    };
  }
  if ($('dns-restore')) {
    $('dns-restore').onclick = async () => {
      if (!window.confirm('把這台的 DNS 改回原本的設定？')) return;
      const r = await dnsDo(() => invoke('dns_restore'));
      if (r) { toast('已改回原本的 DNS'); again(); }
    };
  }
  const inputDomains = () => $('dns-bl-add').value.trim().split(/[\s,]+/).filter(Boolean);
  $('dns-bl-btn').onclick = () => { const v = inputDomains(); if (v.length) dnsListChange('dns_block', v, again); };
  $('dns-al-btn').onclick = () => { const v = inputDomains(); if (v.length) dnsListChange('dns_allow', v, again); };
  $('dns-bl-add').onkeydown = (e) => { if (e.key === 'Enter') $('dns-bl-btn').click(); };
  el.querySelectorAll('[data-unblock]').forEach((b) => (b.onclick = () => dnsListChange('dns_unblock', [b.dataset.unblock], again)));
  el.querySelectorAll('[data-unallow]').forEach((b) => (b.onclick = () => dnsListChange('dns_unallow', [b.dataset.unallow], again)));
}

const DNS_HOWTO = `<details class="card"><summary><b>DNS 防禦怎麼用</b></summary>
  <ol class="small" style="line-height:1.8;margin:8px 0 0 18px;padding:0">
    <li><b>看紀錄</b>：背景服務在跑時，這頁會列出這台查了哪些網域、哪個程式查的；可疑的會標出理由，也會出現在「掃描結果」。</li>
    <li><b>查一個網域</b>：在搜尋框輸入網域按「查詢」（或點紀錄裡的網域），看它現在解析到哪裡、有沒有被威脅情資列名、這台哪些程式查過。</li>
    <li><b>加黑白名單</b>：在紀錄按「封鎖」／「放行」，或在網域分析裡加。黑名單：這台查到就告警、用防護 DNS 的電腦直接被擋；白名單：不告警、不擋（情資誤判時用）。整份清單在「設定 → DNS」管理；全公司一起生效請在 Hub「設定與金鑰 → 防護 DNS」加。</li>
    <li><b>真的擋下來</b>：公司有防護 DNS 時，到「設定 → DNS」按「把這台的 DNS 指過去」；防護 DNS 連不上會自動改回。想讓這台當防護 DNS，在同一處勾「這台當防護 DNS」。</li>
    <li><b>隱私</b>：DNS 紀錄等於上網紀錄，「設定 → DNS」可以改成只傳告警或不傳，也可以整個停用。</li>
  </ol></details>`;

async function pageDns() {
  $main.innerHTML = `<h1>DNS</h1><p class="sub">載入中…</p>`;
  let d;
  try {
    d = await invoke('dns_recent', { minutes: dnsState.minutes, suspicious: dnsState.suspicious, q: dnsState.q });
  } catch (e) {
    $main.innerHTML = `<h1>DNS</h1><div class="card"><p class="small" style="color:var(--danger)">${esc(e)}</p></div>`;
    return;
  }
  const $ = (id) => document.getElementById(id);
  if (!d.enabled) {
    $main.innerHTML = `
      <div class="head"><div><h1>DNS</h1><p class="sub">這台電腦查了哪些網域、是哪個程式查的、哪些可疑。</p></div></div>
      <div class="card notice">
        <div class="notice-ic" aria-hidden="true">⏸</div>
        <div>
          <p class="notice-title">未啟用 DNS 監看</p>
          <p class="small">啟用後會記錄這台查了哪些網域、是哪個程式查的；威脅情資列名、黑名單上、像亂數產生的網域會告警。紀錄只留在這台 7 天，要不要上傳到公司的 Hub 可以在設定裡選。</p>
          <div class="row"><button class="btn primary" id="dns-enable">啟用 DNS 監看</button><a class="btn" href="#settings/dns">到設定</a></div>
        </div>
      </div>`;
    $('dns-enable').onclick = async () => {
      if (await dnsDo(() => invoke('dns_set', { key: 'dns.enabled', value: 'true' }), '已啟用 DNS 監看（背景服務下一輪開始記錄）')) pageDns();
    };
    return;
  }
  const st = d.status;
  const src = st ? DNS_SOURCE[st.source] : null;
  const nxPct = d.total ? Math.round((d.nxdomain / d.total) * 1000) / 10 : 0;
  const domainLink = (name) => `<a class="link mono small" data-domain="${esc(name)}" title="點一下看網域分析">${esc(name)}</a>`;
  $main.innerHTML = `
    <div class="head">
      <div><h1>DNS</h1><p class="sub">這台電腦查了哪些網域、是哪個程式查的、哪些可疑。紀錄只留在這台電腦 7 天${d.upload === 'all' ? '，有加入公司 Hub 時每分鐘上傳' : ''}。</p></div>
      <div class="row">
        <label class="small">期間 <select id="dns-min">${[[15, '15 分鐘'], [60, '1 小時'], [360, '6 小時'], [1440, '24 小時'], [10080, '7 天']].map(([v, l]) => `<option value="${v}" ${v === dnsState.minutes ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <button class="btn" id="dns-refresh">重新整理</button>
        <a class="btn" href="#settings/dns" title="DNS 監看開關、上傳到 Hub、防護 DNS、黑白名單">DNS 設定</a>
      </div>
    </div>
    ${d.unreadable ? `<div class="card"><p class="small">背景服務的 DNS 紀錄要以系統管理員身分執行才讀得到。</p></div>` : ''}
    <div class="grid">
      <div class="stat"><div class="label">查詢次數</div><div class="value">${Number(d.total).toLocaleString()}</div><div class="hint">${src ? `<span title="${esc(src[1])}">來源：${esc(src[0])}</span>` : '背景服務還沒有紀錄'}</div></div>
      <div class="stat"><div class="label" title="${esc(DNS_HINT.domains)}">不同網域 ⓘ</div><div class="value">${Number(d.domains).toLocaleString()}</div></div>
      <div class="stat"><div class="label" title="${esc(DNS_HINT.nx)}">NXDOMAIN ⓘ</div><div class="value">${nxPct}%</div><div class="hint">${Number(d.nxdomain).toLocaleString()} 次</div></div>
      <div class="stat"><div class="label" title="${esc(DNS_HINT.suspicious)}">可疑 ⓘ</div><div class="value" style="${d.suspicious ? 'color:var(--warn)' : ''}">${d.suspicious}</div><div class="hint">${st?.last_event_at ? `最後一筆 ${ago(st.last_event_at)}` : ''}</div></div>
    </div>
    ${DNS_HOWTO}
    <div class="card">
      <form class="filters search-row" id="dns-search" autocomplete="off">
        <input type="search" id="dns-q" data-search placeholder="網域或程式（輸入網域按查詢可看分析）" value="${esc(dnsState.q)}" aria-label="搜尋 DNS 紀錄"/>
        <button class="btn primary" type="submit" title="篩選紀錄；輸入的是網域時另外打開網域分析（快速鍵 Ctrl+F）">查詢</button>
        <label class="small row" title="${esc(DNS_HINT.suspicious)}"><input type="checkbox" id="dns-bad" ${dnsState.suspicious ? 'checked' : ''}/> 只看可疑的 <span class="muted">（${d.suspicious} 筆）</span></label>
        <span class="muted small">${d.records.length >= 500 ? '顯示最近 500 筆' : `顯示 ${d.records.length} 筆`}</span>
      </form>
      ${d.records.length ? `<div class="tbl-wrap"><table><thead><tr><th class="nw">時間</th><th>網域</th><th class="nw">類型</th><th class="nw">結果</th><th class="nw">程式</th><th class="nw">次數</th><th></th></tr></thead><tbody>${d.records
        .map((r) => `<tr>
          <td class="small muted nw">${ago(r.ts)}</td>
          <td>${domainLink(r.name)}${r.reasons.map((x) => ` <span class="chip medium">${esc(x)}</span>`).join('')}${r.answers?.length ? `<div class="small muted mono">${esc(r.answers.slice(0, 3).join(', '))}${r.answers.length > 3 ? '…' : ''}</div>` : ''}</td>
          <td class="small nw">${esc(r.qtype)}</td>
          <td class="small nw">${r.rcode === 'NOERROR' ? '<span class="muted">有答案</span>' : r.rcode === 'NXDOMAIN' ? `<span title="${esc(DNS_HINT.nx)}">查無此網域</span>` : esc(r.rcode)}</td>
          <td class="small">${esc(r.process ?? '—')}</td>
          <td class="small mono nw">${r.count}</td>
          <td class="nw"><button class="btn" data-block="${esc(r.name)}" title="把這個網域（含子網域）加進這台的黑名單">封鎖</button> <button class="btn" data-allow="${esc(r.name)}" title="把這個網域（含子網域）加進這台的白名單：不告警、不擋">放行</button></td>
        </tr>`).join('')}</tbody></table></div>` : `<p class="muted small">${dnsState.q || dnsState.suspicious ? '沒有符合的紀錄。' : '這段期間沒有紀錄（背景服務要在跑才會記錄；Windows 以系統管理員執行才看得到程式）。'}</p>`}
    </div>
    <div class="usage-grid">
      <div class="card"><h2>查詢最多的網域</h2>${d.top_domains.length ? `<table><tbody>${d.top_domains.map((t) => `<tr><td>${domainLink(t.domain)}</td><td class="small muted">${esc(t.process || '')}</td><td class="small mono num">${Number(t.count).toLocaleString()}</td></tr>`).join('')}</tbody></table>` : '<p class="muted small">沒有</p>'}</div>
      <div class="card"><h2>查詢最多的程式</h2>${d.top_processes.length ? `<table><tbody>${d.top_processes.map((t) => `<tr><td class="small">${esc(t.process)}</td><td class="small mono num">${Number(t.count).toLocaleString()}</td></tr>`).join('')}</tbody></table>` : '<p class="muted small">看不到程式（Windows 以系統管理員執行背景服務才看得到）</p>'}</div>
    </div>`;
  $('dns-refresh').onclick = () => pageDns();
  $('dns-min').onchange = (e) => { dnsState.minutes = Number(e.target.value); pageDns(); };
  $('dns-bad').onchange = (e) => { dnsState.suspicious = e.target.checked; pageDns(); };
  const keepFocus = () => { const el = $('dns-q'); if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); } };
  let t = null;
  $('dns-q').oninput = (e) => {
    dnsState.q = e.target.value;
    clearTimeout(t);
    t = setTimeout(() => pageDns().then(keepFocus), 400);
  };
  $('dns-search').onsubmit = (e) => {
    e.preventDefault();
    clearTimeout(t);
    dnsState.q = $('dns-q').value;
    const v = dnsState.q.trim();
    if (isIpLike(v)) showIp(v);
    else if (isDomainLike(v)) showDomain(v);
    pageDns().then(keepFocus);
  };
  $main.querySelectorAll('[data-block]').forEach((b) => (b.onclick = () => dnsListChange('dns_block', [b.dataset.block], pageDns)));
  $main.querySelectorAll('[data-allow]').forEach((b) => (b.onclick = () => dnsListChange('dns_allow', [b.dataset.allow], pageDns)));
}

/** 網域分析的一句話結論。 */
function domainVerdict(r) {
  if (r.allowed) return { tone: 'ok', title: '在白名單上', text: '不告警，也不會被這台跑的防護 DNS 擋下。' };
  if (r.block) return { tone: 'bad', title: '在黑名單上', text: '這台查到就告警；用防護 DNS 的電腦會直接被擋。' };
  if (r.intel.score >= 80) return { tone: 'bad', title: '威脅情資判定危險', text: `${r.intel.hits.length} 份情資清單列名（分數 ${r.intel.score}）。不認得的話建議加入黑名單。` };
  if (r.intel.score >= 60) return { tone: 'warn', title: '威脅情資列為可疑', text: `情資清單列名（分數 ${r.intel.score}），可能是誤報，看一下是哪個程式查的。` };
  if (r.doh) return { tone: 'warn', title: '加密 DNS 端點', text: '程式自己走加密 DNS 會繞過公司的 DNS 防護；瀏覽器以外的程式查它值得留意。' };
  if (r.heuristic) return { tone: 'warn', title: '看起來可疑', text: r.heuristic };
  if (r.popular) return { tone: 'ok', title: '熱門網域', text: '沒有情資列名，是常見的大型網站或服務。' };
  return { tone: 'neutral', title: '沒有發現問題', text: '沒有情資列名、不在黑名單上，也不像亂數產生的網域。' };
}

async function showDomain(raw) {
  const body = openDrawer('網域分析', `<p class="mono big">${esc(raw)}</p><p class="muted small"><span class="spin"></span> 查詢中…</p>`);
  let r;
  try {
    r = await invoke('lookup_domain', { domain: raw });
  } catch (e) {
    if (body.isConnected) body.innerHTML = `<p class="mono big">${esc(raw)}</p><p class="small" style="color:var(--danger)">${esc(e)}</p>`;
    return;
  }
  if (!body.isConnected) return;
  const v = domainVerdict(r);
  const enc = encodeURIComponent(r.domain);
  const intel = !r.intel.loaded
    ? '<span class="muted">情資還沒下載（到「威脅情資」更新）</span>'
    : r.intel.hits.length
      ? r.intel.hits.map((h) => `<a class="link" data-url="${esc(h.source_url)}">${esc(h.vendor)} · ${esc(h.name)}</a> <span class="muted">信心 ${esc(h.confidence)}%</span>`).join('<br>') + `<div class="muted small">網域分數 ${r.intel.score}</div>`
      : '沒有列名';
  const rec = r.recent;
  const acts = [
    r.block?.local ? `<button class="btn" data-dom-act="dns_unblock" data-v="${esc(r.block.entry)}">移出黑名單</button>` : !r.block ? `<button class="btn" data-dom-act="dns_block" data-v="${esc(r.domain)}" title="這個網域（含子網域）加進這台的黑名單">加入黑名單</button>` : '',
    r.allowed_local ? `<button class="btn" data-dom-act="dns_unallow" data-v="${esc(r.allowed_local)}">移出白名單</button>` : !r.allowed ? `<button class="btn" data-dom-act="dns_allow" data-v="${esc(r.domain)}" title="這個網域（含子網域）加進這台的白名單：不告警、不擋">加入白名單</button>` : '',
  ].join('');
  body.innerHTML = `
    <p class="mono big">${esc(r.domain)}</p>
    ${r.registrable && r.registrable !== r.domain ? `<p class="small muted" style="margin-top:-4px" title="${esc(DNS_HINT.domains)}">屬於 <span class="mono">${esc(r.registrable)}</span> (?)</p>` : ''}
    <div class="verdict-box ${v.tone}"><b>${esc(v.title)}</b><div class="small">${esc(v.text)}</div></div>
    <h3>現在解析到</h3>
    ${r.resolved.ok
      ? r.resolved.addrs.length ? `<div class="small">${r.resolved.addrs.map((ip) => `<a class="link mono" data-ip="${esc(ip)}" title="點一下分析這個 IP">${esc(ip)}</a>`).join('<br>')}</div>` : '<p class="small muted">沒有位址</p>'
      : `<p class="small">查不到：${esc(r.resolved.error)}${r.use_hub ? '<br><span class="muted">這台用的是公司的防護 DNS，被擋下的網域也會查不到。</span>' : ''}</p>`}
    <p class="small muted" style="margin-top:4px">用這台電腦目前的 DNS 查的。</p>
    <h3>名單與情資</h3>
    <div class="kv">
      <div>黑名單</div><div>${r.block ? `在黑名單上（${esc(r.block.source)}：<span class="mono">${esc(r.block.entry)}</span>）` : '沒有'}</div>
      <div>白名單</div><div>${r.allowed ? (r.allowed_local ? `在這台的白名單上（<span class="mono">${esc(r.allowed_local)}</span>）` : '在 Hub 的白名單上') : '沒有'}</div>
      <div>威脅情資</div><div>${intel}</div>
      <div title="程式自己走加密 DNS（DoH）會繞過公司的 DNS 防護">加密 DNS 端點 (?)</div><div>${r.doh ? `是（${esc(r.doh)}）` : '不是'}</div>
      <div>其他判斷</div><div>${r.heuristic ? esc(r.heuristic) : r.popular ? '熱門網域' : '沒有'}</div>
    </div>
    <h3>這台最近 7 天</h3>
    ${rec.total
      ? `<p class="small">查了 ${Number(rec.total).toLocaleString()} 次（含子網域），最後一次 ${ago(rec.last)}。</p>
         <table><thead><tr><th>程式</th><th class="num">次數</th></tr></thead><tbody>${rec.processes.map((p) => `<tr><td class="small">${esc(p.process || '（看不到程式）')}</td><td class="small mono num">${p.count}</td></tr>`).join('')}</tbody></table>
         ${rec.names.length > 1 ? `<p class="small muted" style="margin:8px 0 2px">查過的名稱</p>${rec.names.map((n) => `<div class="mono small">${esc(n.name)} <span class="muted">× ${n.count}</span></div>`).join('')}` : ''}
         ${rec.rcodes.some((x) => x.rcode !== 'NOERROR') ? `<p class="small muted" style="margin-top:6px">結果：${rec.rcodes.map((x) => `${esc(x.rcode === 'NOERROR' ? '有答案' : x.rcode === 'NXDOMAIN' ? '查無此網域' : x.rcode)} ${x.count}`).join('、')}</p>` : ''}`
      : '<p class="small muted">這台最近 7 天沒有查過它（或當時沒有啟用 DNS 監看）。</p>'}
    <div class="row" style="margin-top:16px">${acts}<button class="btn primary" id="dom-ai">請 AI 分析這個網域</button></div>
    <div class="row" style="margin-top:8px">
      <button class="btn" data-url="https://www.virustotal.com/gui/domain/${enc}">VirusTotal</button>
      <button class="btn" data-url="https://urlscan.io/search/#domain:${enc}">urlscan.io</button>
    </div>
    <p class="muted small" style="margin-top:8px">外部網站只是連結，按了才會在瀏覽器開啟；ai-security-monitor 不會自動把網域送出去。</p>`;
  body.querySelectorAll('[data-dom-act]').forEach((b) => (b.onclick = () => dnsListChange(b.dataset.domAct, [b.dataset.v], () => {
    showDomain(r.domain);
    if (location.hash === '#dns') pageDns();
  })));
  document.getElementById('dom-ai').onclick = () => goAi('free', `分析這個網域：${r.domain}。用 lookup_ip 查它的威脅情資（indicator 填網域），用 list_connections 看本機有沒有程式正連到它解析出的位址（${r.resolved.addrs?.join('、') || '查不到位址'}）；判斷它大概是什麼服務、是不是誤報，最後給出建議（要不要加黑名單）。`);
}

// ---------------- AI 分析 ----------------
const aiState = { scope: 'connections', prompt: '' };
function goAi(scope, prompt) {
  aiState.scope = scope;
  aiState.prompt = prompt;
  location.hash = '#ai';
}

async function pageAi() {
  $main.innerHTML = `<h1>AI 分析</h1><p class="sub">載入中…</p>`;
  const { providers } = await invoke('ai_providers');
  const usable = providers.filter((p) => p.found);
  $main.innerHTML = `
    <h1>AI 分析</h1>
    <p class="sub">用這台電腦上已登入的 Claude Code 或 Codex CLI（你的訂閱）分析；AI 只能透過 ai-security-monitor 的唯讀工具查資料，不會改動任何設定。</p>
    <div class="card">
      <div class="row" style="margin-bottom:10px">
        <label class="small">AI <select id="prov">${usable.map((p) => `<option value="${p.id}">${esc(p.label)}${p.logged_in ? '' : '（可能未登入）'}</option>`).join('')}</select></label>
        <label class="small">要分析什麼 <select id="scope">
          <option value="connections">可疑連線</option>
          <option value="report">最新掃描報告</option>
          <option value="free">自由提問</option>
        </select></label>
      </div>
      <textarea id="prompt" placeholder="補充問題（可留空）"></textarea>
      <div class="row" style="margin-top:8px"><button class="btn primary" id="go" ${usable.length ? '' : 'disabled'}>開始分析</button><span class="muted small" id="status"></span></div>
      ${usable.length ? '' : `<p class="small" style="color:var(--danger)">找不到 Claude Code 或 Codex CLI。請先安裝並登入其中一個（例如 <span class="mono">npm i -g @anthropic-ai/claude-code</span> 後執行 <span class="mono">claude</span> 登入）。</p>`}
    </div>
    <div class="card"><div id="tools"></div><div id="out" class="ai-out muted">結果會顯示在這裡。</div></div>
    <div class="card" id="ai-accounts"><h2>AI 帳號</h2><p class="muted small"><span class="spin"></span> 正在確認登入狀態…</p></div>`;
  renderAiAccounts();
  document.getElementById('scope').value = aiState.scope;
  document.getElementById('prompt').value = aiState.prompt;
  document.getElementById('go').onclick = runAi;
}

// ---- AI 帳號：這台電腦上的 Claude Code／Codex 登入狀態、登入（開終端機）、登出 ----
const AI_METHOD = { 'claude.ai': 'Claude 訂閱帳號', chatgpt: 'ChatGPT 帳號', api_key: 'API key', oauth_token: '長效 token（環境變數）' };
let aiAuthTimer = null;

async function renderAiAccounts() {
  const box = document.getElementById('ai-accounts');
  if (!box) return;
  let list;
  try {
    list = (await invoke('ai_auth_status')).providers;
  } catch (e) {
    box.innerHTML = `<h2>AI 帳號</h2><p class="small" style="color:var(--danger)">${esc(e)}</p>`;
    return;
  }
  box.innerHTML = `<h2>AI 帳號 <span class="muted small" title="AI 分析用的是這台電腦上的 Claude Code／Codex 程式，也就是你平常用的那個。">(?)</span></h2>
    <table><tbody>${list
      .map(
        (p) => `<tr>
        <td><b>${esc(p.label)}</b></td>
        <td>${!p.installed ? '<span class="chip neutral">未安裝</span>' : p.logged_in ? '<span class="chip ok">已登入</span>' : '<span class="chip medium">未登入</span>'}
          <span class="muted small">${esc([p.email, AI_METHOD[p.method] ?? p.method, p.plan ? String(p.plan).toUpperCase() : null].filter(Boolean).join(' · '))}</span>
          ${p.env_override?.length ? `<div class="small" style="color:var(--warn)">已設環境變數 ${esc(p.env_override.join('、'))}，程式會優先用它。</div>` : ''}</td>
        <td style="text-align:right">${p.installed ? `<button class="btn" data-login="${p.id}">${p.logged_in ? '重新登入' : '登入'}</button>` : ''}
          ${p.installed && p.logged_in ? `<button class="btn" data-logout="${p.id}" style="border-color:var(--danger);color:var(--danger)">登出</button>` : ''}</td>
      </tr>`,
      )
      .join('')}</tbody></table>
    <details class="small" style="margin-top:8px"><summary class="link">怎麼登入？登出會怎樣？</summary>
      <p>按「登入」會開一個終端機視窗執行官方的登入指令（<span class="mono">claude auth login</span>／<span class="mono">codex login</span>），接著會打開瀏覽器，用你的帳號登入並授權就完成，這裡會自動顯示已登入。</p>
      <p>登出會刪掉這台電腦上該程式的登入資料。<b>這就是你平常用的 Claude Code／Codex</b>，登出後你在終端機或編輯器裡用它也要重新登入。</p>
      <p>按鈕不能用時，自己開終端機執行：<span class="mono">claude auth login</span>、<span class="mono">claude auth logout</span>、<span class="mono">codex login</span>、<span class="mono">codex logout</span>。</p>
    </details>`;
  for (const b of box.querySelectorAll('[data-login]')) {
    b.onclick = async () => {
      try {
        await invoke('ai_login', { providerId: b.dataset.login });
        toast('已開啟終端機視窗：照指示在瀏覽器登入，完成後這裡會自動更新', 8000);
        watchAiLogin(b.dataset.login);
      } catch (e) {
        toast(String(e), 8000);
      }
    };
  }
  for (const b of box.querySelectorAll('[data-logout]')) {
    b.onclick = async () => {
      const name = b.dataset.logout === 'claude' ? 'Claude Code' : 'Codex';
      if (!window.confirm(`登出這台電腦上的 ${name}？\n\n這就是你平常用的 ${name}：登出後在終端機或編輯器裡用它也要重新登入。`)) return;
      b.disabled = true;
      try {
        await invoke('ai_logout', { providerId: b.dataset.logout });
        toast(`${name} 已登出`);
      } catch (e) {
        toast(`登出失敗：${e}`, 8000);
      }
      renderAiAccounts();
    };
  }
}

/** 登入是在另一個視窗完成的：每 3 秒問一次，最多 5 分鐘、或離開 AI 頁就停。 */
function watchAiLogin(id) {
  clearInterval(aiAuthTimer);
  const until = Date.now() + 5 * 60_000;
  aiAuthTimer = setInterval(async () => {
    if (location.hash !== '#ai' || Date.now() > until) return clearInterval(aiAuthTimer);
    try {
      const p = (await invoke('ai_auth_status')).providers.find((x) => x.id === id);
      if (p?.logged_in) {
        clearInterval(aiAuthTimer);
        toast(`${p.label} 已登入`);
        renderAiAccounts();
      }
    } catch {
      // 下一輪再問
    }
  }, 3000);
}

let aiUnlisten = null;
let aiText = '';
async function runAi() {
  const go = document.getElementById('go');
  const out = document.getElementById('out');
  const tools = document.getElementById('tools');
  const status = document.getElementById('status');
  aiState.scope = document.getElementById('scope').value;
  aiState.prompt = document.getElementById('prompt').value;
  go.disabled = true;
  aiText = '';
  out.textContent = '';
  out.classList.remove('muted');
  tools.innerHTML = '';
  status.innerHTML = '<span class="spin"></span> 分析中…';
  if (aiUnlisten) aiUnlisten();
  aiUnlisten = await listen('ai-event', ({ payload: e }) => {
    if (e.type === 'text') renderMarkdown(out, (aiText += e.text));
    else if (e.type === 'tool') tools.insertAdjacentHTML('beforeend', `<div class="ai-tool">→ ${esc(e.name)} ${esc(e.input ?? '')}</div>`);
    else if (e.type === 'tool_result' && !e.ok) tools.insertAdjacentHTML('beforeend', `<div class="ai-tool err">✗ ${esc(e.preview)}</div>`);
    else if (e.type === 'start') status.innerHTML = `<span class="spin"></span> ${esc(e.provider)} 分析中…`;
    else if (e.type === 'error') tools.insertAdjacentHTML('beforeend', `<div class="ai-tool err">${esc(e.message)}</div>`);
  });
  try {
    const r = await invoke('ai_ask', { provider: document.getElementById('prov').value, scope: aiState.scope, prompt: aiState.prompt });
    if (!aiText.trim() && r.text) renderMarkdown(out, (aiText = r.text));
    status.textContent = r.is_error ? '結束（有錯誤）' : `完成，呼叫了 ${r.tools_called} 次工具`;
  } catch (e) {
    status.textContent = '';
    tools.insertAdjacentHTML('beforeend', `<div class="ai-tool err">${esc(e)}</div>`);
  } finally {
    go.disabled = false;
  }
}

// ---------------- 設定 ----------------
const BG_HINT = '開機或登入後，在背景定時掃描這台電腦、把結果回報給公司的 Hub。不用開著這個視窗，也不需要系統管理員權限（裝在目前的使用者底下）。';
const PERF_TOGGLE_HINT = '開啟後，每分鐘記錄 CPU、記憶體、磁碟用量與讀寫、最吃資源的程式與電池，送到這台電腦加入的公司 Hub（不會送到其他地方）。Hub 無法從遠端幫你開啟。';
function perfStateText(on) {
  return on
    ? '已開啟。有開「開機／登入後在背景自動回報」時，不用開著這個視窗也會在背景持續蒐集（背景服務每分鐘重讀設定，不用重新啟動）。'
    : '未開啟：只統計網路流量。';
}
const TRAY_HINT = '登入 Windows／macOS／Linux 時自動開啟這個程式，但只放在右下角的系統匣，不會跳出視窗。想看狀況時再點系統匣圖示。';

function serviceText(s) {
  const st = s?.status;
  if (!st) return '—';
  if (s.admin_at_logon) return `已開啟（登入時以系統管理員權限啟動，量得到各程式流量）${s.running ? '・背景回報執行中' : ''}`;
  if (st.installed) return `已開啟${st.state ? `（${esc(st.state)}）` : ''}${s.running ? '・背景回報執行中' : ''}`;
  if (st.legacy) return '找到舊版 asa 的開機啟動：打開這個開關會換成新版（並搬移設定）';
  return s.running ? '沒有設定開機啟動，但目前有背景回報在執行' : '未開啟';
}

/** 設定頁。opts.focus＝'hub' 時捲到 Hub 區塊；opts.search 見 renderHubSection。 */
async function pageSettings(opts = {}) {
  stopJoinPoll();
  const [o, st] = await Promise.all([invoke('overview'), invoke('hub_status')]);
  $main.innerHTML = `
    <h1>設定</h1>
    <p class="sub">桌面版和命令列 ai-security-monitor、背景服務共用同一個設定目錄。</p>
    <div class="card" id="set-hub"></div>
    <div class="card" id="set-dns"><h2>DNS</h2><p class="small muted">讀取中…</p></div>
    <details class="card advanced-card" id="set-lan" hidden></details>
    <div class="card"><h2>背景自動回報與自動更新</h2>
      <label class="row" title="${esc(BG_HINT)}"><input type="checkbox" id="auto-bg" disabled /> <b>開機／登入後在背景自動回報</b> <span class="small muted">(?)</span></label>
      <p class="small muted" id="auto-bg-state" style="margin:4px 0 0 24px">讀取中…</p>
      <div id="set-update"><p class="small muted">讀取更新設定中…</p></div>
    </div>
    <div class="card"><h2>開機自動啟動</h2>
      <label class="row" title="${esc(TRAY_HINT)}"><input type="checkbox" id="auto-tray" disabled /> <b>登入時開啟桌面版（常駐系統匣、不跳視窗）</b> <span class="small muted">(?)</span></label>
      <p class="small muted" style="margin:4px 0 0 24px">關閉這個視窗只會縮到系統匣；從系統匣選「結束」才會離開（自動更新下載好的新版會在這時安裝）。</p>
    </div>
    <div class="card"><h2>網路流量與效能</h2>
      <p class="small muted" style="margin:0 0 8px">網路流量（各網卡、各程式的上傳／下載量）一律統計，有加入公司 Hub 時每分鐘回報。</p>
      <label class="row" title="${esc(PERF_TOGGLE_HINT)}"><input type="checkbox" id="perf-toggle" ${o.metrics?.performance ? 'checked' : ''} /> <b>蒐集這台電腦的效能（CPU、記憶體、磁碟）</b> <span class="small muted">(?)</span></label>
      <p class="small muted" style="margin:4px 0 0 24px" id="perf-state">${perfStateText(o.metrics?.performance)}</p>
    </div>
    <div class="card" id="set-intel"><h2>情資來源授權</h2><p class="small muted">讀取中…</p></div>
    <div class="card"><h2>這台電腦</h2><div class="kv">
      <div>主機名稱</div><div>${esc(o.hostname)}</div>
      <div>agent id</div><div class="mono">${esc(o.agent_id)}</div>
      <div>ai-security-monitor 版本</div><div>${esc(o.version)}</div>
      <div>設定目錄</div><div class="mono">${esc(o.config_dir)}</div>
      <div>系統管理員權限</div><div>${o.elevated ? '是' : '否（部分檢查需要系統管理員才讀得到）'}</div>
    </div></div>`;

  const hubEl = document.getElementById('set-hub');
  renderHubSection(hubEl, st, opts);
  renderUpdateSection(document.getElementById('set-update'));
  renderLanSection(document.getElementById('set-lan'));
  const dnsEl = document.getElementById('set-dns');
  renderDnsSettings(dnsEl);
  const intelEl = document.getElementById('set-intel');
  renderIntelUsageSection(intelEl);
  const focusEl = opts.focus === 'hub' ? hubEl : opts.focus === 'dns' ? dnsEl : opts.focus === 'intel' ? intelEl : null;
  if (focusEl) {
    focusEl.scrollIntoView({ block: 'start' });
    focusEl.classList.add('focus');
    setTimeout(() => focusEl.classList.remove('focus'), 1600);
  }

  // 開機自動啟動：兩個開關各自讀狀態
  const bg = document.getElementById('auto-bg');
  const bgState = document.getElementById('auto-bg-state');
  const tray = document.getElementById('auto-tray');
  invoke('background_service_status')
    .then((s) => {
      bg.checked = !!s.status?.installed || !!s.admin_at_logon;
      bg.dataset.admin = s.admin_at_logon ? '1' : '';
      bg.disabled = false;
      bgState.textContent = serviceText(s);
    })
    .catch((e) => (bgState.textContent = `無法讀取：${e}`));
  bg.onchange = async () => {
    const want = bg.checked;
    bg.disabled = true;
    bgState.innerHTML = `<span class="spin"></span> ${want ? '設定中…' : '移除中…'}`;
    try {
      // 目前是「以系統管理員權限啟動」：關掉要先刪排程工作（會跳 UAC）
      if (!want && bg.dataset.admin) await invoke('set_admin_logon', { enabled: false });
      const r = await invoke('set_background_service', { enabled: want });
      bg.checked = !!r.status?.status?.installed || !!r.status?.admin_at_logon;
      bg.dataset.admin = r.status?.admin_at_logon ? '1' : '';
      bgState.textContent = serviceText(r.status);
      toast(want ? '已開啟背景自動回報' : '已關閉背景自動回報');
      renderUpdateSection(document.getElementById('set-update'));
      renderLanSection(document.getElementById('set-lan'));
    } catch (e) {
      bg.checked = !want;
      bgState.textContent = `失敗：${e}`;
    } finally {
      bg.disabled = false;
    }
  };
  invoke('desktop_autostart_status')
    .then((on) => {
      tray.checked = !!on;
      tray.disabled = false;
    })
    .catch(() => {});
  const perf = document.getElementById('perf-toggle');
  perf.onchange = async () => {
    const want = perf.checked;
    perf.disabled = true;
    try {
      perf.checked = await invoke('set_performance', { enabled: want });
      document.getElementById('perf-state').textContent = perfStateText(perf.checked);
      toast(perf.checked ? '已開啟效能蒐集' : '已關閉效能蒐集');
    } catch (e) {
      perf.checked = !want;
      toast(String(e), 8000);
    } finally {
      perf.disabled = false;
    }
  };
  tray.onchange = async () => {
    const want = tray.checked;
    tray.disabled = true;
    try {
      tray.checked = await invoke('set_desktop_autostart', { enabled: want });
      toast(want ? '登入時會在系統匣開啟' : '登入時不會自動開啟');
    } catch (e) {
      tray.checked = !want;
      toast(String(e), 8000);
    } finally {
      tray.disabled = false;
    }
  };
}

// ---------------- 即時流量 ----------------
const liveState = { points: [], window: 60, total: { rx: 0, tx: 0 }, since: null, timer: null, last: null, lastAt: 0 };
const LIVE_MAX = 300;

/** 位元速率（網路業者常用的單位）：bytes/s → Mbps 等。 */
const fmtBits = (bps) => {
  const b = Math.max(0, bps) * 8;
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} Gbps`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(b >= 1e8 ? 0 : 1)} Mbps`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(0)} Kbps`;
  return `${Math.round(b)} bps`;
};

/** 大圖：下載（藍綠）、上傳（琥珀）兩條線，Y 軸自動縮放並標刻度。 */
function liveChart(points, windowS) {
  const W = 720;
  const H = 200;
  const PAD_L = 64;
  const PAD_B = 18;
  const data = points.slice(-windowS);
  const max = Math.max(1024, ...data.map((p) => Math.max(p.rx, p.tx)));
  const nice = (() => {
    const steps = [1, 2, 5];
    let unit = 1024;
    while (true) {
      for (const s of steps) if (s * unit >= max) return s * unit;
      unit *= 10;
    }
  })();
  const x = (i) => PAD_L + (i / Math.max(1, windowS - 1)) * (W - PAD_L - 4);
  const offset = windowS - data.length;
  const y = (v) => H - PAD_B - (Math.min(v, nice) / nice) * (H - PAD_B - 8);
  const path = (key) =>
    data.map((p, i) => `${i ? 'L' : 'M'}${x(i + offset).toFixed(1)},${y(p[key]).toFixed(1)}`).join('');
  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((f) => {
      const yy = y(nice * f).toFixed(1);
      return `<line x1="${PAD_L}" x2="${W - 4}" y1="${yy}" y2="${yy}" class="live-grid"/><text x="${PAD_L - 6}" y="${(+yy + 4).toFixed(1)}" text-anchor="end" class="live-axis">${fmtRate(nice * f)}</text>`;
    })
    .join('');
  const ticks = [windowS, Math.round(windowS / 2), 0]
    .map((s) => `<text x="${x(windowS - 1 - s).toFixed(1)}" y="${H - 4}" text-anchor="${s === windowS ? 'start' : s ? 'middle' : 'end'}" class="live-axis">${s ? `${s} 秒前` : '現在'}</text>`)
    .join('');
  return `<svg class="live-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="最近 ${windowS} 秒的下載與上傳速率">${grid}${ticks}
    ${data.length > 1 ? `<path d="${path('rx')}" class="live-rx"/><path d="${path('tx')}" class="live-tx"/>` : ''}</svg>`;
}

function stopLive() {
  clearTimeout(liveState.timer);
  liveState.timer = null;
}

async function pageTraffic() {
  stopLive();
  // 離開這一頁超過 10 秒再回來：舊的線接不上，重新畫
  if (Date.now() - liveState.lastAt > 10_000) liveState.points = [];
  $main.innerHTML = `
    <div class="head">
      <div><h1>即時流量</h1><p class="sub">這台電腦現在的下載／上傳速度，每秒更新（只在這一頁開著時量，不會存起來）。</p></div>
      <div class="row">
        <div class="seg" id="live-win">
          <button class="fchip ${liveState.window === 60 ? 'on' : ''}" data-w="60">60 秒</button>
          <button class="fchip ${liveState.window === 300 ? 'on' : ''}" data-w="300">5 分鐘</button>
        </div>
        <button class="btn" id="live-reset" title="把「這次累計」歸零">歸零</button>
      </div>
    </div>
    <div class="grid">
      <div class="stat"><div class="label"><span class="dot rx"></span> 下載</div><div class="value" id="lv-rx">—</div><div class="hint" id="lv-rxb"></div></div>
      <div class="stat"><div class="label"><span class="dot tx"></span> 上傳</div><div class="value" id="lv-tx">—</div><div class="hint" id="lv-txb"></div></div>
      <div class="stat"><div class="label">這次累計</div><div class="value" style="font-size:18px;padding-top:6px" id="lv-total">—</div><div class="hint" id="lv-since"></div></div>
    </div>
    <div class="card"><h2>速率（最近 <span id="lv-win-label">${liveState.window === 60 ? '60 秒' : '5 分鐘'}</span>）</h2><div id="lv-chart"><p class="muted small"><span class="spin"></span> 量測中…</p></div></div>
    <div class="split" style="grid-template-columns:1fr 1fr">
      <div class="card"><h2>各網路卡 <span class="muted small" title="虛擬網卡（VPN、Docker、WSL、Hyper-V）的流量其實也會經過實體網卡，所以不算進上面的總量">(?)</span></h2><div id="lv-ifaces" class="muted small">量測中…</div></div>
      <div class="card"><h2>哪個程式在用網路</h2><div id="lv-procs" class="muted small">量測中…</div></div>
    </div>`;
  for (const b of document.querySelectorAll('#live-win [data-w]')) {
    b.onclick = () => {
      liveState.window = Number(b.dataset.w);
      for (const x of document.querySelectorAll('#live-win [data-w]')) x.classList.toggle('on', x === b);
      document.getElementById('lv-win-label').textContent = liveState.window === 60 ? '60 秒' : '5 分鐘';
      renderLive();
    };
  }
  document.getElementById('live-reset').onclick = () => {
    liveState.total = { rx: 0, tx: 0 };
    liveState.since = Date.now();
    renderLive();
  };
  if (!liveState.since) liveState.since = Date.now();
  tickLive();
}

async function tickLive() {
  stopLive();
  if (location.hash !== '#traffic') return;
  // 視窗縮到系統匣或切到別的分頁時不量（省資源），回來再接著量
  if (document.visibilityState === 'visible') {
    try {
      const r = await invoke('traffic_live');
      if (r.ready) {
        liveState.last = r;
        liveState.lastAt = Date.now();
        liveState.points.push({ rx: r.rx_rate, tx: r.tx_rate });
        if (liveState.points.length > LIVE_MAX) liveState.points.splice(0, liveState.points.length - LIVE_MAX);
        liveState.total.rx += r.rx_bytes;
        liveState.total.tx += r.tx_bytes;
        renderLive();
      }
    } catch (e) {
      const el = document.getElementById('lv-chart');
      if (el) el.innerHTML = `<p class="small" style="color:var(--danger)">${esc(e)}</p>`;
    }
  }
  if (location.hash === '#traffic') liveState.timer = setTimeout(tickLive, 1000);
}

function renderLive() {
  const r = liveState.last;
  const chart = document.getElementById('lv-chart');
  if (!chart || !r) return;
  document.getElementById('lv-rx').textContent = fmtRate(r.rx_rate);
  document.getElementById('lv-tx').textContent = fmtRate(r.tx_rate);
  document.getElementById('lv-rxb').textContent = fmtBits(r.rx_rate);
  document.getElementById('lv-txb').textContent = fmtBits(r.tx_rate);
  document.getElementById('lv-total').textContent = `↓ ${fmtBytes(liveState.total.rx)} · ↑ ${fmtBytes(liveState.total.tx)}`;
  document.getElementById('lv-since').textContent = `從 ${new Date(liveState.since).toLocaleTimeString()} 起`;
  chart.innerHTML = liveChart(liveState.points, liveState.window);
  const ifaces = r.interfaces ?? [];
  document.getElementById('lv-ifaces').innerHTML = ifaces.length
    ? `<table><thead><tr><th>網路卡</th><th style="text-align:right">下載</th><th style="text-align:right">上傳</th></tr></thead><tbody>${ifaces
        .map(
          (i) => `<tr><td>${esc(i.name)}${i.virtual ? ' <span class="chip neutral" title="虛擬網卡：流量其實也經過實體網卡，不算進總量">虛擬</span>' : ''}</td>
            <td class="mono" style="text-align:right">${fmtRate(i.rx_rate)}</td><td class="mono" style="text-align:right">${fmtRate(i.tx_rate)}</td></tr>`,
        )
        .join('')}</tbody></table>`
    : '<p class="muted">沒有讀到網路卡。</p>';
  const procs = r.processes;
  const el = document.getElementById('lv-procs');
  if (!procs) {
    el.innerHTML =
      r.os === 'windows'
        ? `<p class="small">Windows 要用<b>系統管理員</b>身分執行桌面版，才看得到每個程式的用量（系統只對系統管理員開放這項統計）。</p><p class="small muted">想知道哪個程式連到哪裡，可以看「<a class="link" href="#connections">連線</a>」頁。</p>`
        : r.os === 'linux'
          ? '<p class="small">Linux 沒有不裝額外工具就能讀到各程式用量的方法；想知道哪個程式連到哪裡，請看「<a class="link" href="#connections">連線</a>」頁。</p>'
          : '<p class="small muted">這次沒有讀到各程式的用量。</p>';
    return;
  }
  const active = procs.filter((p) => p.rx_rate + p.tx_rate > 0);
  el.innerHTML = active.length
    ? `<table><thead><tr><th>程式</th><th style="text-align:right">下載</th><th style="text-align:right">上傳</th></tr></thead><tbody>${active
        .map((p) => `<tr><td><b>${esc(p.name)}</b></td><td class="mono" style="text-align:right">${fmtRate(p.rx_rate)}</td><td class="mono" style="text-align:right">${fmtRate(p.tx_rate)}</td></tr>`)
        .join('')}</tbody></table><p class="small muted" style="margin-top:6px">${r.process_source === 'estats' ? '只算 TCP 連線的資料量（Windows 延伸統計）。' : '來源：macOS nettop。'}</p>`
    : '<p class="muted">這一秒沒有程式在收發資料。</p>';
}

// ---------------- 路由 ----------------
// 網址是 #頁面 或 #頁面/區塊：#settings/hub、#settings/dns＝設定頁的 Hub／DNS 區塊；#traffic/1h、#traffic/24h＝流量與效能的歷史分頁（#traffic 是即時）
// 「流量與效能」（traffic）由 usage.js 的 pageTrafficTabs 分成即時／最近 1 小時／最近 24 小時三個分頁
const PAGES = { overview: pageOverview, connections: pageConnections, dns: pageDns, traffic: pageTrafficTabs, findings: pageFindings, intel: pageIntel, ai: pageAi, settings: pageSettings };
async function route() {
  let [page, section] = (location.hash || '#overview').slice(1).split('/');
  let opts = section === 'hub' || section === 'dns' || section === 'intel' ? { focus: section } : { section };
  if (page === 'join') {
    // 舊的「加入公司 Hub」頁已經併進設定頁：換成設定頁的 Hub 區塊並直接開始尋找
    history.replaceState(null, '', HUB_SECTION);
    page = 'settings';
    opts = { focus: 'hub', search: true };
  }
  stopJoinPoll();
  stopUsageRefresh();
  for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', a.dataset.page === page);
  try {
    await (PAGES[page] ?? pageOverview)(opts);
  } catch (e) {
    $main.innerHTML = `<h1>出錯了</h1><p class="sub">${esc(e)}</p>`;
  }
}
window.addEventListener('hashchange', route);
// 第一次開啟、還沒加入任何 Hub：先帶到設定頁的 Hub 區塊（按過「先不要」就不再自動帶）
// 還沒選情資的使用情境（公司／個人）：蓋在畫面上問一次
(async () => {
  promptIntelUsageIfNeeded();
  if (!location.hash) {
    try {
      const st = await invoke('hub_status');
      if (st.pending || (!st.hub_url && !joinSkipped())) {
        location.hash = HUB_SECTION;
        return;
      }
    } catch {
      // 讀不到 Hub 狀態就照常開總覽
    }
  }
  route();
})();
