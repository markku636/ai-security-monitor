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
});

// ---------------- 總覽 ----------------
async function pageOverview() {
  $main.innerHTML = `<h1>總覽</h1><p class="sub">載入中…</p>`;
  const o = await invoke('overview');
  document.getElementById('brand-host').textContent = o.hostname || o.report?.hostname || '本機';
  document.getElementById('side-foot').innerHTML = `ai-security-monitor ${esc(o.version)}<br>${o.watcher_running ? '背景服務執行中' : '背景服務沒有在跑'}`;
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
      <div class="stat"><div class="label">Security Hub</div><div class="value" style="font-size:15px;padding-top:8px">${o.hub_url ? '已註冊' : '未註冊'}</div><div class="hint">${o.hub_url ? `<span class="mono">${esc(o.hub_url)}</span>` : `<a class="link" href="${HUB_SECTION}">尋找公司的 Hub</a>`}</div></div>
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

/** 小折線圖（一條或兩條線；pct 時固定 0–100）。 */
function sparkline(series, { pct = false, label = '' } = {}) {
  const W = 160;
  const H = 36;
  const all = series.flatMap((s) => s.values).filter((v) => v != null);
  if (all.length < 2) return '<div class="spark-empty">累積幾分鐘後會畫出變化</div>';
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
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(label)}">${lines}</svg>`;
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
        <td><span class="chip ${esc(c.verdict.level)}">${VERDICT[c.verdict.level] ?? esc(c.verdict.level)}</span></td>
        <td><span class="chip dir">${DIRECTION[c.direction] ?? esc(c.direction)}</span><div class="muted small">${esc(c.proto)} · ${esc(c.state)}</div></td>
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
  sort: { key: 'verdict', dir: 1 },
  auto: false,
  timer: null,
};

const REASON_KIND = { intel: '情資', behavior: '行為', none: '沒有理由' };
const REASON_HINT = { intel: '有威脅情資清單列名', behavior: 'asa 自己的行為判斷（例如週期性連線、新目的地）', none: '沒有任何可疑理由' };

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

async function pageConnections() {
  $main.innerHTML = `
    <div class="head">
      <div><h1>連線</h1><p class="sub">這台電腦目前的連線，依威脅情資與異常行為判定；點 IP 可看詳細分析，點表頭可排序。</p></div>
      <div class="row">
        <label class="small row"><input type="checkbox" id="auto" ${connState.auto ? 'checked' : ''}/> 每 10 秒更新</label>
        <button class="btn" id="refresh">重新整理</button>
        <button class="btn primary" id="ask">請 AI 分析可疑連線</button>
      </div>
    </div>
    <div class="split">
      <div>
        <div class="card">
          <div class="filters" id="f-verdict"></div>
          <div class="filters" id="f-dir"></div>
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
          <div class="filters"><input type="text" id="q" placeholder="IP、程式或組織" value="${esc(connState.q)}" style="width:260px"/><button class="btn" id="f-clear">清除篩選</button><span class="muted small" id="count"></span></div>
          <div id="tbl" class="muted">載入中…</div>
        </div>
      </div>
      <div id="ip-panel"></div>
    </div>`;
  document.getElementById('refresh').onclick = () => loadConns();
  document.getElementById('ask').onclick = () => goAi('connections', '');
  document.getElementById('q').oninput = (e) => { connState.q = e.target.value; renderConns(); };
  document.getElementById('f-port').oninput = (e) => { connState.port = e.target.value.replace(/\D/g, ''); renderConns(); };
  document.getElementById('f-public').onchange = (e) => { connState.publicOnly = e.target.checked; renderConns(); };
  document.getElementById('f-loop').onchange = (e) => { connState.hideLoopback = e.target.checked; renderConns(); };
  document.getElementById('f-process').onchange = (e) => { connState.process = e.target.value; renderConns(); };
  document.getElementById('f-country').onchange = (e) => { connState.country = e.target.value; renderConns(); };
  document.getElementById('f-clear').onclick = () => {
    for (const k of ['verdict', 'direction', 'proto', 'state', 'reason']) connState[k].clear();
    Object.assign(connState, { process: '', country: '', port: '', publicOnly: false, hideLoopback: false, q: '' });
    pageConnections();
  };
  document.getElementById('tbl').addEventListener('click', (e) => {
    const th = e.target.closest('th[data-sort]');
    if (!th) return;
    const key = th.dataset.sort;
    connState.sort = connState.sort.key === key ? { key, dir: -connState.sort.dir } : { key, dir: key === 'n' ? -1 : 1 };
    renderConns();
  });
  document.getElementById('auto').onchange = (e) => { connState.auto = e.target.checked; setAuto(); };
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
    document.getElementById('tbl').textContent = String(e);
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
      `<span class="muted small" style="width:40px">${label}</span>` +
      entries(counts)
        .map(([v, l]) => `<button class="fchip ${set.has(v) ? 'on' : ''}" data-set="${el}" data-v="${esc(v)}" ${hints[v] ? `title="${esc(hints[v])}"` : ''}>${esc(l)} <span class="muted">${counts.get(v) ?? 0}</span></button>`)
        .join('');
  };
  const SETS = { 'f-verdict': connState.verdict, 'f-dir': connState.direction, 'f-proto': connState.proto, 'f-state': connState.state, 'f-reason': connState.reason };
  chipRow('f-verdict', '判定', connState.verdict, () => Object.entries(VERDICT), (c) => c.verdict.level);
  chipRow('f-dir', '方向', connState.direction, () => Object.entries(DIRECTION), (c) => c.direction);
  chipRow('f-proto', '協定', connState.proto, (m) => [...m.keys()].sort().map((v) => [v, v.toUpperCase()]), (c) => String(c.proto ?? '').toLowerCase());
  chipRow('f-state', '狀態', connState.state, (m) => [...m.entries()].sort((a, b) => b[1] - a[1]).map(([v]) => [v, v || '—']), (c) => c.state ?? '');
  chipRow('f-reason', '理由', connState.reason, () => Object.entries(REASON_KIND), reasonKind, REASON_HINT);
  for (const b of document.querySelectorAll('.fchip[data-set]')) {
    b.onclick = () => {
      const set = SETS[b.dataset.set];
      set.has(b.dataset.v) ? set.delete(b.dataset.v) : set.add(b.dataset.v);
      renderConns();
    };
  }
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
      (!q || [c.remote_ip, c.process?.name, c.geo?.org, c.geo?.country].some((x) => String(x ?? '').toLowerCase().includes(q))),
  );
  const groups = sortGroups(groupConns(rows));
  document.getElementById('count').textContent = `${rows.length} 條連線（合併成 ${groups.length} 列）`;
  document.getElementById('tbl').innerHTML = groups.length ? connTable(groups) : '<div class="empty">沒有符合的連線</div>';
}

async function showIp(ip) {
  if (location.hash !== '#connections') { location.hash = '#connections'; await new Promise((r) => setTimeout(r, 300)); }
  const p = document.getElementById('ip-panel');
  if (!p) return;
  p.innerHTML = `<div class="card"><h2>IP 分析</h2><p class="mono">${esc(ip)}</p><p class="muted">查詢中…</p></div>`;
  try {
    const r = await invoke('lookup_ip', { ip });
    const conns = lastConns.filter((c) => c.remote_ip === ip);
    p.innerHTML = `<div class="card">
      <h2>IP 分析</h2>
      <p class="mono" style="font-size:16px;margin:0 0 8px">${esc(ip)}</p>
      <div class="kv">
        <div>國家</div><div>${esc(r.geo?.country ?? '—')}</div>
        <div>組織／ASN</div><div>${esc(r.geo?.org ?? '—')}${r.geo?.asn ? ` (AS${esc(r.geo.asn)})` : ''}</div>
        <div>位址類型</div><div>${esc(r.class)}</div>
      </div>
      <h2 style="margin-top:14px">情資命中</h2>
      ${r.hits.length ? r.hits.map((h) => `<div class="small" style="margin-bottom:4px"><a class="link" data-url="${esc(h.source_url)}">${esc(h.vendor)} · ${esc(h.name)}</a> <span class="muted">信心 ${esc(h.confidence)}% · ${esc(h.license ?? '')}</span></div>`).join('') : '<p class="muted small">沒有任何情資來源列名（若被判可疑，是行為判斷）。</p>'}
      <h2 style="margin-top:14px">本機哪些程式連它</h2>
      ${conns.length ? [...new Set(conns.map((c) => `${c.process?.name ?? '—'}（${c.state}）`))].map((x) => `<div class="small">${esc(x)}</div>`).join('') : '<p class="muted small">目前沒有連線。</p>'}
      <div class="row" style="margin-top:14px">
        <button class="btn primary" id="ip-ai">請 AI 分析這個 IP</button>
        <button class="btn" data-url="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}">VirusTotal</button>
        <button class="btn" data-url="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}">AbuseIPDB</button>
      </div>
      <p class="muted small" style="margin-top:8px">外部網站只是連結，按了才會在瀏覽器開啟。</p>
    </div>`;
    document.getElementById('ip-ai').onclick = () => goAi('free', `分析這個 IP：${ip}。用 lookup_ip 查情資與國家／ASN，用 list_connections 看本機哪些程式連它；判斷它大概是什麼服務、被判可疑的理由是情資還是行為判斷、是不是誤報，最後給出建議。`);
  } catch (e) {
    p.innerHTML = `<div class="card">${esc(e)}</div>`;
  }
}

// ---------------- 掃描結果 ----------------
async function pageFindings() {
  $main.innerHTML = `<h1>掃描結果</h1><p class="sub">載入中…</p>`;
  const r = await invoke('latest_report');
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const fs = (r?.findings ?? []).slice().sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  $main.innerHTML = `
    <div class="head">
      <div><h1>掃描結果</h1><p class="sub">${r ? `最後掃描 ${ago(r.finished_at)}，共 ${fs.length} 筆` : '還沒有掃描報告'}</p></div>
      <div class="row"><button class="btn primary" id="scan">立即掃描</button><button class="btn" id="ask">請 AI 解讀這份報告</button></div>
    </div>
    <div class="card">${fs.length ? `<table><thead><tr><th>嚴重度</th><th>問題</th><th>類別</th></tr></thead><tbody>${fs
      .map((f) => `<tr>
        <td><span class="chip ${esc(f.severity)}">${SEVERITY[f.severity] ?? esc(f.severity)}</span></td>
        <td><details><summary><b>${esc(f.title)}</b></summary>
          <p class="small">${esc(f.detail)}</p>
          ${f.recommendation ? `<p class="small"><b>建議：</b>${esc(f.recommendation)}</p>` : ''}
          ${(f.intel_hits ?? []).map((h) => `<span class="reason intel" data-url="${esc(h.source_url)}"><span class="k">情資</span>${esc(h.vendor)} ${esc(h.confidence)}%</span>`).join('')}
        </details></td>
        <td class="small muted">${esc(f.scanner)}<div class="mono">${esc(f.rule)}</div></td>
      </tr>`).join('')}</tbody></table>` : '<div class="empty">沒有問題，或還沒掃描過。</div>'}</div>`;
  document.getElementById('scan').onclick = () => scanNow();
  document.getElementById('ask').onclick = () => goAi('report', '');
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
    <div class="card"><table><thead><tr><th>來源</th><th>種類</th><th>筆數</th><th>最後更新</th><th>授權</th></tr></thead><tbody>${feeds
      .map((f) => `<tr>
        <td><a class="link" data-url="${esc(f.source_url)}"><b>${esc(f.vendor)}</b> ${esc(f.name)}</a>${f.enabled ? '' : ' <span class="chip neutral">已停用</span>'}</td>
        <td class="small">${esc(f.kind)}</td>
        <td class="small mono">${f.entries ? Number(f.entries).toLocaleString() : '—'}</td>
        <td class="small">${ago(f.fetched_at)}${f.from_hub ? ' <span class="chip dir">Hub</span>' : ''}${f.status === 'error' ? ` <span class="chip medium" title="${esc(f.error)}">失敗</span>` : ''}${f.status === 'never' ? ' <span class="chip neutral">未下載</span>' : ''}</td>
        <td class="small muted">${esc(f.license)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  document.getElementById('upd').onclick = () => updateIntel(false);
  document.getElementById('force').onclick = () => updateIntel(true);
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
    <div class="card" id="set-lan" hidden></div>
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
  if (opts.focus === 'hub') {
    hubEl.scrollIntoView({ block: 'start' });
    hubEl.classList.add('focus');
    setTimeout(() => hubEl.classList.remove('focus'), 1600);
  }

  // 開機自動啟動：兩個開關各自讀狀態
  const bg = document.getElementById('auto-bg');
  const bgState = document.getElementById('auto-bg-state');
  const tray = document.getElementById('auto-tray');
  invoke('background_service_status')
    .then((s) => {
      bg.checked = !!s.status?.installed;
      bg.disabled = false;
      bgState.textContent = serviceText(s);
    })
    .catch((e) => (bgState.textContent = `無法讀取：${e}`));
  bg.onchange = async () => {
    const want = bg.checked;
    bg.disabled = true;
    bgState.innerHTML = `<span class="spin"></span> ${want ? '設定中…' : '移除中…'}`;
    try {
      const r = await invoke('set_background_service', { enabled: want });
      bg.checked = !!r.status?.status?.installed;
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

// ---------------- 路由 ----------------
// 網址是 #頁面 或 #頁面/區塊（目前只有 #settings/hub：設定頁的 Hub 區塊）
const PAGES = { overview: pageOverview, connections: pageConnections, findings: pageFindings, intel: pageIntel, ai: pageAi, settings: pageSettings };
async function route() {
  let [page, section] = (location.hash || '#overview').slice(1).split('/');
  let opts = section === 'hub' ? { focus: 'hub' } : {};
  if (page === 'join') {
    // 舊的「加入公司 Hub」頁已經併進設定頁：換成設定頁的 Hub 區塊並直接開始尋找
    history.replaceState(null, '', HUB_SECTION);
    page = 'settings';
    opts = { focus: 'hub', search: true };
  }
  stopJoinPoll();
  for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', a.dataset.page === page);
  try {
    await (PAGES[page] ?? pageOverview)(opts);
  } catch (e) {
    $main.innerHTML = `<h1>出錯了</h1><p class="sub">${esc(e)}</p>`;
  }
}
window.addEventListener('hashchange', route);
// 第一次開啟、還沒加入任何 Hub：先帶到設定頁的 Hub 區塊（按過「先不要」就不再自動帶）
(async () => {
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
