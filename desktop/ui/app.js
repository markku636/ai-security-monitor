// AI Security Agent 桌面版介面：純 HTML／JS，透過 Tauri 指令呼叫 asa 程式庫。
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
      return `<span class="reason behavior" title="${esc(`asa 自己的行為判斷，不是情資來源\n${r.detail ?? ''}`)}"><span class="k">行為</span>${esc(ANOMALY[r.kind] ?? r.kind)}</span>`;
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
  document.getElementById('side-foot').innerHTML = `asa ${esc(o.version)}<br>${o.watcher_running ? '背景服務執行中' : '背景服務沒有在跑'}`;
  const r = o.report;
  const s = r?.score;
  const bar = (label, v) => `<div class="stat"><div class="label">${label}</div><div class="value">${v ?? '—'}</div><div class="bar"><i style="width:${v ?? 0}%"></i></div></div>`;
  const intelOld = !o.intel.checked_at || Date.now() - Date.parse(o.intel.checked_at) > 6 * 3600e3;
  $main.innerHTML = `
    <div class="head">
      <div><h1>總覽</h1><p class="sub">這台電腦目前的安全狀況（資料與背景的 asa 共用）。</p></div>
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
      <div class="stat"><div class="label">Security Hub</div><div class="value" style="font-size:15px;padding-top:8px">${o.hub_url ? '已註冊' : '未註冊'}</div><div class="hint mono">${esc(o.hub_url ?? 'asa enroll <網址> --key …')}</div></div>
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
    <p class="sub">用這台電腦上已登入的 Claude Code 或 Codex CLI（你的訂閱）分析；AI 只能透過 asa 的唯讀工具查資料，不會改動任何設定。</p>
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
async function pageSettings() {
  const o = await invoke('overview');
  $main.innerHTML = `
    <h1>設定</h1>
    <p class="sub">桌面版和命令列 asa、背景服務共用同一個設定目錄。</p>
    <div class="card"><h2>這台電腦</h2><div class="kv">
      <div>主機名稱</div><div>${esc(o.hostname)}</div>
      <div>agent id</div><div class="mono">${esc(o.agent_id)}</div>
      <div>asa 版本</div><div>${esc(o.version)}</div>
      <div>設定目錄</div><div class="mono">${esc(o.config_dir)}</div>
      <div>系統管理員權限</div><div>${o.elevated ? '是' : '否（部分檢查需要系統管理員才讀得到）'}</div>
    </div></div>
    <div class="card"><h2>Security Hub</h2><div class="kv">
      <div>狀態</div><div>${o.hub_url ? '已註冊' : '未註冊'}</div>
      <div>網址</div><div>${o.hub_url ? `<a class="link" data-url="${esc(o.hub_url)}">${esc(o.hub_url)}</a>` : '—'}</div>
    </div>
    ${o.hub_url ? '' : '<p class="small muted">要集中管理多台電腦：在 Hub 的「新增主機」頁建立註冊金鑰，然後在命令列執行 <span class="mono">asa enroll &lt;Hub 網址&gt; --key &lt;金鑰&gt; --yes</span>。</p>'}</div>
    <div class="card"><h2>背景服務</h2>
      <p class="small">${o.watcher_running ? '✓ 背景的 asa watch 正在執行：定時掃描、上傳到 Hub、每 30 分鐘更新情資。' : '背景服務沒有在跑。命令列執行 <span class="mono">asa service install --user --yes</span> 讓它登入時自動啟動。'}</p>
      <p class="small muted">關閉這個視窗只會縮到系統匣；從系統匣選「結束」才會離開。</p>
    </div>`;
}

// ---------------- 路由 ----------------
const PAGES = { overview: pageOverview, connections: pageConnections, findings: pageFindings, intel: pageIntel, ai: pageAi, settings: pageSettings };
async function route() {
  const page = (location.hash || '#overview').slice(1);
  for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', a.dataset.page === page);
  try {
    await (PAGES[page] ?? pageOverview)();
  } catch (e) {
    $main.innerHTML = `<h1>出錯了</h1><p class="sub">${esc(e)}</p>`;
  }
}
window.addEventListener('hashchange', route);
route();
