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
      <div class="stat"><div class="label">Security Hub</div><div class="value" style="font-size:15px;padding-top:8px">${o.hub_url ? '已註冊' : '未註冊'}</div><div class="hint">${o.hub_url ? `<span class="mono">${esc(o.hub_url)}</span>` : '<a class="link" href="#join">尋找公司的 Hub</a>'}</div></div>
    </div>
    <div class="card"><h2>危險與可疑連線</h2><div id="ov-conn" class="muted">載入中…</div></div>`;
  document.getElementById('scan').onclick = () => scanNow();
  document.getElementById('upd').onclick = () => updateIntel(false);
  try {
    const c = await invoke('connections');
    const bad = c.connections.filter((x) => x.verdict.level === 'dangerous' || x.verdict.level === 'suspicious');
    document.getElementById('ov-conn').innerHTML = bad.length
      ? connTable(groupConns(bad).slice(0, 8))
      : '<p class="muted">目前沒有可疑或危險的連線。</p>';
  } catch (e) {
    document.getElementById('ov-conn').textContent = String(e);
  }
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

function connTable(rows) {
  return `<table><thead><tr><th>判定</th><th>方向</th><th>遠端</th><th>國家／組織</th><th>程式</th><th>理由與來源</th></tr></thead><tbody>${rows
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
        <td>${remote}${n > 1 ? `<div class="muted small">× ${n} 條連線</div>` : ''}</td>
        <td class="small">${geo}</td>
        <td class="small"><b>${esc(c.process?.name ?? '—')}</b>${c.process?.pid != null ? `<div class="muted">pid ${esc(c.process.pid)}</div>` : ''}</td>
        <td>${(c.verdict.reasons ?? []).map(reasonHtml).join('') || '<span class="muted">—</span>'}</td>
      </tr>`;
    })
    .join('')}</tbody></table>`;
}

const connState = { verdict: new Set(['dangerous', 'suspicious']), direction: new Set(), q: '', auto: false, timer: null };

async function pageConnections() {
  $main.innerHTML = `
    <div class="head">
      <div><h1>連線</h1><p class="sub">這台電腦目前的連線，依威脅情資與異常行為判定；點 IP 可看詳細分析。</p></div>
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
          <div class="filters"><input type="text" id="q" placeholder="IP、程式或組織" value="${esc(connState.q)}" style="width:260px"/><span class="muted small" id="count"></span></div>
          <div id="tbl" class="muted">載入中…</div>
        </div>
      </div>
      <div id="ip-panel"></div>
    </div>`;
  document.getElementById('refresh').onclick = () => loadConns();
  document.getElementById('ask').onclick = () => goAi('connections', '');
  document.getElementById('q').oninput = (e) => { connState.q = e.target.value; renderConns(); };
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
    renderConns();
  } catch (e) {
    document.getElementById('tbl').textContent = String(e);
  }
}

function renderConns() {
  const fv = document.getElementById('f-verdict');
  if (!fv) return;
  const count = (k, v) => lastConns.filter((c) => (k === 'v' ? c.verdict.level : c.direction) === v).length;
  const chip = (set, v, label, k) => `<button class="fchip ${set.has(v) ? 'on' : ''}" data-k="${k}" data-v="${v}">${label} <span class="muted">${count(k, v)}</span></button>`;
  fv.innerHTML = `<span class="muted small" style="width:40px">判定</span>` + Object.entries(VERDICT).map(([v, l]) => chip(connState.verdict, v, l, 'v')).join('');
  document.getElementById('f-dir').innerHTML = `<span class="muted small" style="width:40px">方向</span>` + Object.entries(DIRECTION).map(([v, l]) => chip(connState.direction, v, l, 'd')).join('');
  for (const b of document.querySelectorAll('.fchip')) {
    b.onclick = () => {
      const set = b.dataset.k === 'v' ? connState.verdict : connState.direction;
      set.has(b.dataset.v) ? set.delete(b.dataset.v) : set.add(b.dataset.v);
      renderConns();
    };
  }
  const q = connState.q.trim().toLowerCase();
  const rows = lastConns.filter((c) =>
    (!connState.verdict.size || connState.verdict.has(c.verdict.level)) &&
    (!connState.direction.size || connState.direction.has(c.direction)) &&
    (!q || [c.remote_ip, c.process?.name, c.geo?.org, c.geo?.country].some((x) => String(x ?? '').toLowerCase().includes(q))));
  const groups = groupConns(rows);
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
    <div class="card"><div id="tools"></div><div id="out" class="ai-out muted">結果會顯示在這裡。</div></div>`;
  document.getElementById('scope').value = aiState.scope;
  document.getElementById('prompt').value = aiState.prompt;
  document.getElementById('go').onclick = runAi;
}

let aiUnlisten = null;
async function runAi() {
  const go = document.getElementById('go');
  const out = document.getElementById('out');
  const tools = document.getElementById('tools');
  const status = document.getElementById('status');
  aiState.scope = document.getElementById('scope').value;
  aiState.prompt = document.getElementById('prompt').value;
  go.disabled = true;
  out.textContent = '';
  out.classList.remove('muted');
  tools.innerHTML = '';
  status.innerHTML = '<span class="spin"></span> 分析中…';
  if (aiUnlisten) aiUnlisten();
  aiUnlisten = await listen('ai-event', ({ payload: e }) => {
    if (e.type === 'text') out.textContent += e.text;
    else if (e.type === 'tool') tools.insertAdjacentHTML('beforeend', `<div class="ai-tool">→ ${esc(e.name)} ${esc(e.input ?? '')}</div>`);
    else if (e.type === 'tool_result' && !e.ok) tools.insertAdjacentHTML('beforeend', `<div class="ai-tool err">✗ ${esc(e.preview)}</div>`);
    else if (e.type === 'start') status.innerHTML = `<span class="spin"></span> ${esc(e.provider)} 分析中…`;
    else if (e.type === 'error') tools.insertAdjacentHTML('beforeend', `<div class="ai-tool err">${esc(e.message)}</div>`);
  });
  try {
    const r = await invoke('ai_ask', { provider: document.getElementById('prov').value, scope: aiState.scope, prompt: aiState.prompt });
    if (!out.textContent.trim() && r.text) out.textContent = r.text;
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
const TRAY_HINT = '登入 Windows／macOS／Linux 時自動開啟這個程式，但只放在右下角的系統匣，不會跳出視窗。想看狀況時再點系統匣圖示。';
const NEEDS_CONFIRM = 'needs_confirm:';

// 換到別的 Hub（指紋不同）要使用者明確確認；確認後帶 confirmed 再呼叫一次
async function invokeConfirmed(cmd, args) {
  try {
    return await invoke(cmd, { ...args, confirmed: false });
  } catch (e) {
    const msg = String(e);
    if (!msg.startsWith(NEEDS_CONFIRM)) throw e;
    const ok = window.confirm(`${msg.slice(NEEDS_CONFIRM.length)}\n\n請先和管理員確認新的 Hub 指紋。確定要換到這個 Hub？`);
    if (!ok) return null;
    return invoke(cmd, { ...args, confirmed: true });
  }
}

function serviceText(s) {
  const st = s?.status;
  if (!st) return '—';
  if (st.installed) return `已開啟${st.state ? `（${esc(st.state)}）` : ''}${s.running ? '・背景回報執行中' : ''}`;
  if (st.legacy) return '找到舊版 asa 的開機啟動：打開這個開關會換成新版（並搬移設定）';
  return s.running ? '沒有設定開機啟動，但目前有背景回報在執行' : '未開啟';
}

async function pageSettings() {
  stopJoinPoll();
  const o = await invoke('overview');
  const st = await invoke('hub_status');
  $main.innerHTML = `
    <h1>設定</h1>
    <p class="sub">桌面版和命令列 ai-security-monitor、背景服務共用同一個設定目錄。</p>
    <div class="card"><h2>公司的 Security Hub</h2>
      <div class="kv">
        <div>狀態</div><div>${st.hub_url ? '已加入' : st.pending ? `等候管理員核准（<a class="link" href="#join">查看</a>）` : '未加入（只在這台電腦使用）'}</div>
        <div title="${esc(FP_HINT)}">Hub 指紋 (?)</div><div class="mono">${esc(st.hub_fingerprint ?? '—')}</div>
      </div>
      <div class="row" style="margin-top:10px">
        <input type="text" id="hub-url" placeholder="https://hub.example.com" value="${esc(st.hub_url ?? st.pending?.hub_url ?? '')}" style="flex:1;min-width:260px" title="管理員給的 Hub 網址。必須是 https；公司內網（例如 192.168.x.x）或本機可以用 http。" />
      </div>
      <div class="row" style="margin-top:8px">
        <button class="btn" id="hub-test" title="確認這個網址連得到、是 Security Hub，並顯示它的版本與指紋">測試連線</button>
        <a class="btn" href="#join" title="用公司 DNS 與區網廣播自動找 Hub">尋找公司的 Hub</a>
        <button class="btn primary" id="hub-join" title="不需要金鑰：送出加入申請，管理員在 Hub 核准後就完成">申請加入</button>
        ${st.hub_url ? '<button class="btn" id="hub-leave" title="這台電腦不再回報給這個 Hub">離開這個 Hub</button>' : ''}
      </div>
      <div id="hub-result" class="small" style="margin-top:8px"></div>
      <details style="margin-top:8px"><summary class="small">我有註冊金鑰（進階）</summary>
        <p class="small muted">管理員也可以在 Hub「新增主機」頁建立註冊金鑰（asa_ek_…）給你，用金鑰加入就不必等核准。</p>
        <div class="row"><input type="text" id="hub-key" placeholder="asa_ek_…" style="flex:1;min-width:260px" autocomplete="off" spellcheck="false" /><button class="btn" id="hub-key-go">用金鑰加入</button></div>
      </details>
    </div>
    <div class="card"><h2>開機自動啟動</h2>
      <label class="row" title="${esc(BG_HINT)}"><input type="checkbox" id="auto-bg" disabled /> <b>開機／登入後在背景自動回報</b> <span class="small muted">(?)</span></label>
      <p class="small muted" id="auto-bg-state" style="margin:4px 0 10px 24px">讀取中…</p>
      <label class="row" title="${esc(TRAY_HINT)}"><input type="checkbox" id="auto-tray" disabled /> <b>登入時開啟桌面版（常駐系統匣、不跳視窗）</b> <span class="small muted">(?)</span></label>
      <p class="small muted" style="margin:4px 0 0 24px">關閉這個視窗只會縮到系統匣；從系統匣選「結束」才會離開。</p>
    </div>
    <div class="card"><h2>這台電腦</h2><div class="kv">
      <div>主機名稱</div><div>${esc(o.hostname)}</div>
      <div>agent id</div><div class="mono">${esc(o.agent_id)}</div>
      <div>ai-security-monitor 版本</div><div>${esc(o.version)}</div>
      <div>設定目錄</div><div class="mono">${esc(o.config_dir)}</div>
      <div>系統管理員權限</div><div>${o.elevated ? '是' : '否（部分檢查需要系統管理員才讀得到）'}</div>
    </div></div>`;

  const $res = document.getElementById('hub-result');
  const url = () => document.getElementById('hub-url').value.trim();
  const busy = (b, on, label) => {
    b.disabled = on;
    if (on) {
      b.dataset.label = b.textContent;
      b.innerHTML = `<span class="spin"></span> ${label}`;
    } else if (b.dataset.label) b.textContent = b.dataset.label;
  };

  document.getElementById('hub-test').onclick = async (ev) => {
    if (!url()) return toast('請先輸入 Hub 網址');
    busy(ev.currentTarget, true, '測試中…');
    try {
      const c = await invoke('hub_check', { url: url() });
      const id = c.identity;
      $res.innerHTML = `✓ 連得到 <span class="mono">${esc(c.url)}</span>：${esc(id?.name ?? 'Security Hub')} ${esc(c.health?.version ?? '')}
        ${id ? `・指紋 <span class="mono">${esc(id.fingerprint)}</span>` : '・這個 Hub 版本較舊，沒有身分指紋（只能用註冊金鑰加入）'}
        ${c.fingerprint_changed ? '<br><b style="color:var(--danger)">注意：這個 Hub 的指紋和這台電腦目前加入的不同。可能是另一個 Hub，或 Hub 重新安裝過；請先和管理員確認。</b>' : ''}`;
    } catch (e) {
      $res.innerHTML = `<span style="color:var(--danger)">✗ ${esc(e)}</span>`;
    } finally {
      busy(ev.currentTarget, false);
    }
  };

  document.getElementById('hub-join').onclick = async (ev) => {
    if (!url()) return toast('請先輸入 Hub 網址，或按「尋找公司的 Hub」');
    const b = ev.currentTarget;
    busy(b, true, '確認 Hub…');
    try {
      const c = await invoke('hub_check', { url: url() });
      if (!c.identity) throw new Error('這個 Hub 版本較舊，不支援免金鑰加入；請用註冊金鑰');
      if (!window.confirm(`申請加入「${c.identity.name}」？\n網址：${c.url}\n指紋：${c.identity.fingerprint}\n\n請確認指紋和管理員給的一樣。`)) return;
      const r = await invokeConfirmed('request_join', { url: c.url, fingerprint: c.identity.fingerprint });
      if (r) location.hash = '#join';
    } catch (e) {
      $res.innerHTML = `<span style="color:var(--danger)">✗ ${esc(e)}</span>`;
    } finally {
      busy(b, false);
    }
  };

  document.getElementById('hub-key-go').onclick = async (ev) => {
    const key = document.getElementById('hub-key').value.trim();
    if (!url() || !key) return toast('請輸入 Hub 網址與註冊金鑰');
    const b = ev.currentTarget;
    busy(b, true, '加入中…');
    try {
      const r = await invokeConfirmed('enroll_with_key', { url: url(), key });
      if (r) {
        toast('已用金鑰加入 Hub');
        pageSettings();
      }
    } catch (e) {
      $res.innerHTML = `<span style="color:var(--danger)">✗ ${esc(e)}</span>`;
    } finally {
      busy(b, false);
    }
  };

  const leave = document.getElementById('hub-leave');
  if (leave) {
    leave.onclick = async () => {
      if (!window.confirm('離開這個 Hub？\n\n這台電腦會停止回報、刪除這台保存的 Hub 金鑰。Hub 上這台主機的紀錄不會自動刪除，需要的話請管理員在 Hub 的「主機」頁刪除。')) return;
      try {
        await invoke('leave_hub');
        toast('已離開 Hub');
        pageSettings();
      } catch (e) {
        toast(String(e), 8000);
      }
    };
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

// ---------------- 加入公司的 Security Hub ----------------
const SOURCE = { explicit: '指定的網址', env: '環境變數', config: '設定檔', dns_srv: '公司 DNS', mdns: '區網廣播' };
const FP_HINT = '指紋是 Hub 的身分證號碼。請和管理員在 Hub「新增主機」頁看到的指紋比對，一樣才是公司的 Hub。';
const CODE_HINT = '管理員在「待核准的主機」清單上會看到同一組核對碼，用來確認是這台電腦。';
const SKIP_KEY = 'asm.join.skipped';
let joinTimer = null;

function stopJoinPoll() {
  clearTimeout(joinTimer);
  joinTimer = null;
}

function waitingCard(p) {
  return `<div class="card"><h2>等候管理員核准</h2>
    <p class="small">已送出加入申請到 <b>${esc(p.hub_name)}</b>（<span class="mono">${esc(p.hub_url)}</span>）。請管理員到 Hub 的「新增主機 → 待核准的主機」核對下面兩組號碼後按「核准」。</p>
    <div class="kv">
      <div title="${esc(FP_HINT)}">Hub 指紋 (?)</div><div class="mono">${esc(p.hub_fingerprint)}</div>
      <div title="${esc(CODE_HINT)}">這台電腦的核對碼 (?)</div><div class="mono" style="font-size:16px">${esc(p.request_code)}</div>
      <div>送出時間</div><div>${esc(ago(p.created_at))}</div>
    </div>
    <p class="small muted" id="join-state"><span class="spin"></span> 等候中，會自動確認…（關掉視窗也沒關係，背景服務會繼續等）</p>
    <div class="row"><button class="btn" id="join-check">現在確認</button><button class="btn" id="join-cancel">取消申請</button></div>
  </div>`;
}

async function pollJoin(auto) {
  stopJoinPoll();
  const el = document.getElementById('join-state');
  const again = (ms) => {
    if (location.hash === '#join') joinTimer = setTimeout(() => pollJoin(true), ms);
  };
  try {
    const r = await invoke('join_poll');
    if (r.status === 'approved') {
      toast(`管理員已核准：已加入 ${r.hub_name}`);
      location.hash = '#overview';
      return;
    }
    if (r.status === 'rejected') {
      $main.innerHTML = `<h1>加入公司的 Security Hub</h1><div class="card"><h2>申請被拒絕</h2><p class="small">管理員拒絕了這台電腦的加入申請${r.reason ? `：${esc(r.reason)}` : ''}。如有疑問請聯絡管理員。</p><div class="row"><button class="btn" id="join-again">重新尋找</button></div></div>`;
      document.getElementById('join-again').onclick = () => pageJoin(true);
      return;
    }
    if (r.status === 'expired' || r.status === 'none') {
      toast('加入申請已過期或被刪除，請重新申請');
      pageJoin(true);
      return;
    }
    if (el && !auto) el.innerHTML = '<span class="spin"></span> 還沒核准，稍後會再自動確認…';
    again(Math.max(5, r.poll_interval_s || 15) * 1000);
  } catch (e) {
    if (el) el.textContent = `確認失敗：${e}（稍後重試）`;
    again(30000);
  }
}

const normFp = (s) => String(s ?? '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();

function hubRows(list, pinned) {
  return list
    .map((h, i) => {
      const id = h.identity;
      const ok = id && !h.error && id.enrollment?.keyless;
      const pin = pinned && id && normFp(id.fingerprint) === normFp(pinned);
      const why = h.error ?? (id && !id.enrollment?.keyless ? '這個 Hub 不接受免金鑰加入' : '無法使用');
      return `<tr>
        <td><b>${esc(id?.name ?? '—')}</b><div class="small muted mono">${esc(h.url)}</div></td>
        <td><span class="chip neutral">${esc(SOURCE[h.source] ?? h.source)}</span>${h.detail ? `<div class="small muted">${esc(h.detail)}</div>` : ''}</td>
        <td class="mono" title="${esc(FP_HINT)}">${esc(id?.fingerprint ?? '—')}${pin ? ' <span class="chip ok">這台記得的</span>' : ''}</td>
        <td>${ok ? `<button class="btn primary" data-join="${i}">申請加入</button>` : `<span class="small muted">${esc(why)}</span>`}</td>
      </tr>`;
    })
    .join('');
}

async function searchHubs(url) {
  const box = document.getElementById('join-found');
  box.innerHTML = '<p class="muted"><span class="spin"></span> 正在尋找（公司 DNS、區網廣播），約 3–10 秒…</p>';
  try {
    const r = await invoke('discover_hubs', { url: url || null });
    if (!r.hubs.length) {
      box.innerHTML = '<p class="small">沒有找到 Security Hub。請管理員在公司 DNS 加 <span class="mono">_ai-security-monitor._tcp</span> 的 SRV 紀錄、或在區網開啟 Hub 廣播；也可以在下面直接輸入管理員給的 Hub 網址。</p>';
      return;
    }
    box.innerHTML = `<table><thead><tr><th>Hub</th><th>找到的方式</th><th title="${esc(FP_HINT)}">指紋 (?)</th><th></th></tr></thead><tbody>${hubRows(r.hubs, r.pinned_fingerprint)}</tbody></table>
      <p class="small muted">找到好幾個時，請先問管理員公司的 Hub 指紋是哪一個。</p>`;
    for (const b of box.querySelectorAll('[data-join]')) {
      b.onclick = async () => {
        const h = r.hubs[Number(b.dataset.join)];
        if (!window.confirm(`申請加入「${h.identity.name}」？\n網址：${h.url}\n指紋：${h.identity.fingerprint}\n\n請確認指紋和管理員給的一樣。`)) return;
        b.disabled = true;
        try {
          await invoke('request_join', { url: h.url, fingerprint: h.identity.fingerprint });
          pageJoin(false);
        } catch (e) {
          toast(String(e), 8000);
          b.disabled = false;
        }
      };
    }
  } catch (e) {
    box.innerHTML = `<p class="small">尋找失敗：${esc(e)}</p>`;
  }
}

async function pageJoin(search = true) {
  stopJoinPoll();
  const st = await invoke('hub_status');
  if (st.pending) {
    $main.innerHTML = `<h1>加入公司的 Security Hub</h1><p class="sub">加入後，這台電腦的安全狀況會定期回報到公司的 Hub，由管理員集中查看。</p>${waitingCard(st.pending)}`;
    document.getElementById('join-check').onclick = () => pollJoin(false);
    document.getElementById('join-cancel').onclick = async () => {
      if (!window.confirm('取消這次的加入申請？')) return;
      await invoke('cancel_join');
      pageJoin(true);
    };
    pollJoin(true);
    return;
  }
  $main.innerHTML = `
    <h1>尋找公司的 Security Hub</h1>
    <p class="sub">不需要金鑰：找到公司的 Hub 後按「申請加入」，等管理員核准就完成。${st.hub_url ? `（這台電腦目前已加入 <span class="mono">${esc(st.hub_url)}</span>）` : ''}</p>
    <div class="card"><h2>找到的 Hub</h2><div id="join-found"></div>
      <div class="row" style="margin-top:10px"><button class="btn" id="join-search">重新尋找</button></div></div>
    <div class="card"><h2>或輸入管理員給的 Hub 網址</h2>
      <div class="row"><input type="text" id="join-url" placeholder="https://hub.example.com" style="flex:1;min-width:240px" /><button class="btn" id="join-url-go">查詢這個網址</button></div>
    </div>
    <p class="small muted"><a class="link" href="#overview" id="join-skip">先不要，只在這台電腦使用</a></p>`;
  document.getElementById('join-search').onclick = () => searchHubs();
  document.getElementById('join-url-go').onclick = () => searchHubs(document.getElementById('join-url').value.trim());
  document.getElementById('join-skip').onclick = () => {
    try {
      localStorage.setItem(SKIP_KEY, '1');
    } catch {}
  };
  if (search) searchHubs();
  else document.getElementById('join-found').innerHTML = '<p class="muted small">按「重新尋找」開始。</p>';
}

// ---------------- 路由 ----------------
const PAGES = { overview: pageOverview, connections: pageConnections, findings: pageFindings, intel: pageIntel, ai: pageAi, settings: pageSettings, join: () => pageJoin(true) };
async function route() {
  const page = (location.hash || '#overview').slice(1);
  if (page !== 'join') stopJoinPoll();
  for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', a.dataset.page === page);
  try {
    await (PAGES[page] ?? pageOverview)();
  } catch (e) {
    $main.innerHTML = `<h1>出錯了</h1><p class="sub">${esc(e)}</p>`;
  }
}
window.addEventListener('hashchange', route);
// 第一次開啟、還沒加入任何 Hub：先帶到「尋找公司的 Security Hub」（按過「先不要」就不再自動帶）
(async () => {
  if (!location.hash) {
    try {
      const st = await invoke('hub_status');
      let skipped = false;
      try {
        skipped = localStorage.getItem(SKIP_KEY) === '1';
      } catch {}
      if (st.pending || (!st.hub_url && !skipped)) {
        location.hash = '#join';
        return;
      }
    } catch {}
  }
  route();
})();
