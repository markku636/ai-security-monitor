// AI Security Monitor 桌面版：自動更新（右下角提示、設定頁）、立即上傳到 Hub（總覽頁）、
// 讓區網找到這台的 Hub（設定頁）、尋找 Hub 時的說明（設定頁的 Hub 區塊，見 hub-join.js）。
// 和 app.js 共用 invoke／listen／esc／toast／ago（app.js 定義）；這個檔先載入，只定義函式，畫面載入後才執行。
'use strict';

const UPDATE_MODES = [
  { id: 'off', label: '關閉', hint: '不檢查新版。要更新時自己按「檢查更新」。' },
  { id: 'notify', label: '有新版時通知我（建議）', hint: '每天檢查一次；有新版會在右下角提醒，你按「立即更新」才會更新。' },
  {
    id: 'auto',
    label: '自動更新',
    hint: '每天檢查一次；有新版會先在背景下載好，下次結束或重新開啟這個程式時自動安裝（安裝檔有數位簽章，驗證過才裝）。',
  },
];
const BG_UPDATE_HINT = '背景自動回報用的就是桌面版本身，所以會跟著桌面版一起更新，不用另外處理。';
const LAN_HINT =
  '這台電腦上有在跑 Security Hub。打開後，背景自動回報會在區網廣播（mDNS，跟印表機被自動找到的原理一樣）告訴同一個網路的電腦 Hub 在哪裡，同事按「尋找同網段 Hub」就會看到它。';
const LAN_URL_HINT =
  '區網裡的電腦要連的網址：這台的區網 IP＋Hub 的 port。Hub 只綁 127.0.0.1（單機版的預設）時區網連不到，要先在 Hub 的 .env 設 AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0 並重新啟動 Hub。';

// ---------------- 右下角的新版提示 ----------------
const banner = { el: null, dismissed: null, version: null };

function bannerEl() {
  if (!banner.el) {
    banner.el = document.createElement('div');
    banner.el.className = 'update-banner';
    banner.el.hidden = true;
    banner.el.setAttribute('role', 'status');
    document.body.appendChild(banner.el);
  }
  return banner.el;
}

function showUpdateBanner(kind, info) {
  const v = info?.version;
  if (!v || banner.dismissed === `${kind}:${v}`) return;
  banner.version = v;
  const el = bannerEl();
  const notes = info.notes_url ? `<a class="link" data-url="${esc(info.notes_url)}">看更新內容</a>` : '';
  if (kind === 'ready') {
    el.innerHTML = `<div><b>新版 ${esc(v)} 已下載好</b><div class="small muted">${info.requires_confirmation ? '按「立即更新」，輸入系統管理員密碼即可完成。' : '結束或重新開啟這個程式時會自動安裝。'}</div></div>
      <div class="row"><button class="btn primary" data-up="install">${info.requires_confirmation ? '立即更新' : '現在重新啟動並更新'}</button><button class="btn" data-up="close" title="先不要">×</button></div>`;
  } else if (kind === 'installing') {
    el.innerHTML = `<div><span class="spin"></span> 正在安裝新版 ${esc(v)}，程式會自動重新開啟…</div>`;
  } else {
    el.innerHTML = `<div><b>有新版 ${esc(v)}</b><div class="small muted">目前 ${esc(info.current ?? '')} ${notes}</div></div>
      <div class="row"><button class="btn primary" data-up="install">立即更新</button><button class="btn" data-up="close" title="先不要">×</button></div>`;
  }
  el.hidden = false;
  for (const b of el.querySelectorAll('[data-up]')) {
    b.onclick = () => {
      if (b.dataset.up === 'close') {
        banner.dismissed = `${kind}:${v}`;
        el.hidden = true;
      } else installUpdateNow(b);
    };
  }
}

async function installUpdateNow(btn) {
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> 下載並安裝中…';
  }
  try {
    // Windows 會啟動安裝程式並結束這個程式；macOS／Linux 裝好後自動重新開啟
    await invoke('install_update');
  } catch (e) {
    toast(`更新失敗：${e}`, 8000);
    if (btn) {
      btn.disabled = false;
      btn.textContent = '立即更新';
    }
  }
}

function initUpdateEvents() {
  listen('update-available', (e) => {
    if (e.payload?.mode !== 'auto') showUpdateBanner('available', { ...e.payload, current: window.__asmVersion });
  });
  listen('update-ready', (e) => showUpdateBanner('ready', e.payload));
  listen('update-error', (e) => toast(`更新失敗：${e.payload?.error ?? '請稍後重試'}`, 8000));
  listen('update-installing', (e) => showUpdateBanner('installing', e.payload));
  listen('update-progress', (e) => {
    const p = e.payload ?? {};
    const pct = p.total ? Math.min(100, Math.round((p.downloaded / p.total) * 100)) : null;
    const el = document.getElementById('upd-progress');
    if (el) el.textContent = pct != null ? `下載中 ${pct}%` : '下載中…';
  });
  // 背景已經查過、有新版：開啟時就顯示
  invoke('update_status')
    .then((s) => {
      window.__asmVersion = s.current;
      if (s.desktop?.ready) showUpdateBanner('ready', { version: s.desktop.latest, requires_confirmation: !s.auto_install_ok });
      else if (s.desktop?.available && s.mode !== 'off') showUpdateBanner('available', { version: s.desktop.latest, notes_url: s.desktop.notes_url, current: s.current });
    })
    .catch(() => {});
}
window.addEventListener('DOMContentLoaded', initUpdateEvents);

// ---------------- 設定頁：自動更新 ----------------
function versionLine(s) {
  const d = s.desktop ?? {};
  const latest = d.latest
    ? d.available
      ? `<b style="color:var(--accent)">有新版 ${esc(d.latest)}</b>${d.ready ? '（已下載好）' : ''}`
      : `已是最新版`
    : '還沒檢查';
  const when = d.checked_at ? `<span class="muted">（${esc(ago(d.checked_at))}檢查）</span>` : '';
  const err = d.error ? `<div class="small" style="color:var(--danger)">檢查失敗：${esc(d.error)}</div>` : '';
  return `桌面版 <b>${esc(s.current)}</b> · ${latest} ${when}${err}`;
}

function backgroundLine(s) {
  const b = s.background ?? {};
  const rows = [];
  if (b.uses_desktop) rows.push(`<div>背景自動回報：用桌面版本身（版本同上）<span class="muted" title="${esc(BG_UPDATE_HINT)}"> (?)</span></div>`);
  for (const c of b.cli ?? []) {
    rows.push(`<div>另外裝的命令列版背景服務 <span class="mono">${esc(c.exe)}</span>：${esc(c.version ?? '版本不明')}
      ${c.newer ? `· <b style="color:var(--accent)">有新版 ${esc(c.latest)}</b> <button class="btn" data-cli="${esc(c.exe)}" title="下載、比對 SHA256 後替換，並重新啟動這個背景服務">更新命令列版</button>` : ''}
      <div class="small muted">命令列版照它自己的 update.mode 更新（和這裡是同一個設定）。</div></div>`);
  }
  if (!rows.length) rows.push('<div class="muted">背景自動回報沒有在跑（打開上面的開關才會在背景回報）。</div>');
  return rows.join('');
}

async function renderUpdateSection(el, status) {
  let s = status;
  try {
    s ??= await invoke('update_status');
  } catch (e) {
    el.innerHTML = `<p class="small">無法讀取更新設定：${esc(e)}</p>`;
    return;
  }
  window.__asmVersion = s.current;
  const d = s.desktop ?? {};
  const notesUrl = d.notes_url ?? s.releases_url;
  el.innerHTML = `
    <div style="margin-top:14px"><b>自動更新</b> <span class="small muted" title="桌面版和它的背景自動回報用同一個設定；另外裝的命令列版也照這個設定。">(?)</span></div>
    <div class="radio-list">${UPDATE_MODES.map(
      (m) => `<label class="row" title="${esc(m.hint)}"><input type="radio" name="upd-mode" value="${m.id}" ${s.mode === m.id ? 'checked' : ''}/> ${esc(m.label)}</label>
        <div class="small muted radio-hint">${esc(m.hint)}</div>`,
    ).join('')}</div>
    ${s.blocker ? `<p class="small" style="color:var(--warn)">${esc(s.blocker)}。</p>` : ''}
    ${!s.auto_install_ok ? '<p class="small muted">這台是用 .deb 安裝的：自動更新會先下載，要你按「立即更新」並輸入系統管理員密碼才會安裝。</p>' : ''}
    <div class="small" style="margin-top:10px" id="upd-version">${versionLine(s)}</div>
    <div class="row" style="margin-top:8px">
      <button class="btn" id="upd-check" title="現在就到 GitHub 查有沒有新版（不管上面設成什麼）">檢查更新</button>
      <button class="btn primary" id="upd-now" ${d.available && !s.blocker ? '' : 'disabled'} title="下載、驗證簽章後安裝，裝完自動重新開啟；背景自動回報一起換成新版">立即更新</button>
      <a class="link small" data-url="${esc(notesUrl)}">看更新內容</a>
      <span class="small muted" id="upd-progress"></span>
    </div>
    <div class="small" style="margin-top:10px">${backgroundLine(s)}</div>`;
  for (const r of el.querySelectorAll('input[name=upd-mode]')) {
    r.onchange = async () => {
      try {
        const n = await invoke('set_update_mode', { mode: r.value });
        toast(`自動更新：${UPDATE_MODES.find((m) => m.id === n.mode)?.label ?? n.mode}`);
        renderUpdateSection(el, n);
      } catch (e) {
        toast(String(e), 8000);
      }
    };
  }
  document.getElementById('upd-check').onclick = async (ev) => {
    const b = ev.currentTarget;
    b.disabled = true;
    b.innerHTML = '<span class="spin"></span> 檢查中…';
    try {
      const n = await invoke('check_updates');
      toast(n.desktop?.error ? `檢查失敗：${n.desktop.error}` : n.desktop?.available ? `有新版 ${n.desktop.latest}` : `已是最新版（${n.current}）`);
      renderUpdateSection(el, n);
    } catch (e) {
      toast(String(e), 8000);
      b.disabled = false;
      b.textContent = '檢查更新';
    }
  };
  document.getElementById('upd-now').onclick = (ev) => installUpdateNow(ev.currentTarget);
  for (const b of el.querySelectorAll('[data-cli]')) {
    b.onclick = async () => {
      if (!window.confirm(`更新命令列版背景服務？\n${b.dataset.cli}\n\n會下載新版、比對 SHA256 後替換，並重新啟動這個背景服務。`)) return;
      b.disabled = true;
      b.innerHTML = '<span class="spin"></span> 更新中…';
      try {
        const r = await invoke('update_cli_agent', { exe: b.dataset.cli });
        toast(r.to ? `命令列版已更新到 ${r.to}` : '已是最新版');
      } catch (e) {
        toast(`更新失敗：${e}`, 8000);
      }
      renderUpdateSection(el);
    };
  }
}

// ---------------- 設定頁：讓區網找到這台的 Hub ----------------
function advertisingText(s) {
  const a = s.advertising;
  if (!s.advertise_url) return '未開啟。';
  if (!s.background_running || !a || a.stale) return '<span style="color:var(--warn)">背景自動回報沒有在跑：打開「開機／登入後在背景自動回報」才會一直廣播。</span>';
  const i = a.info ?? {};
  if (i.state === 'advertising') return `<span style="color:var(--ok)">廣播中</span>（指紋 <span class="mono">${esc(i.fingerprint ?? '—')}</span>，${esc(ago(i.since))}開始）`;
  if (i.state === 'starting') return '<span class="spin"></span> 準備中…（約 1 分鐘內開始）';
  return `<span style="color:var(--danger)">沒有在廣播：${esc(i.error ?? '連不到 Hub')}</span>（用這個網址連不到 Hub 時會自動暫停，連得到了再自動恢復）`;
}

async function renderLanSection(el) {
  const wasOpen = el.open;
  let s;
  try {
    s = await invoke('local_hub_status');
  } catch {
    el.hidden = true;
    return;
  }
  // 只有這台電腦上有在跑 Hub（或之前開過廣播）才顯示
  if (!s.found && !s.advertise_url) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  const url = s.advertise_url ?? s.suggested_url ?? '';
  const badge = !s.advertise_url
    ? '<span class="chip neutral">未開啟</span>'
    : s.advertising?.info?.state === 'advertising' && !s.advertising?.stale
      ? '<span class="chip ok">廣播中</span>'
      : '<span class="chip medium">需檢查</span>';
  el.innerHTML = `<summary><b>進階：讓其他電腦找到這台的 Hub</b>${badge}<span class="muted small">僅 Hub 主機需要</span></summary>
    <div class="advanced-body">
    <p class="small muted">這是給「這台電腦本身也在執行 Hub」的管理員使用，和上方讓本機加入 Hub 的方式不同；一般使用者不需要設定。</p>
    ${s.found ? `<p class="small">本機 Hub：<b>${esc(s.name ?? 'Security Hub')}</b>（127.0.0.1:${esc(s.port)}，指紋 <span class="mono">${esc(s.fingerprint ?? '—')}</span>）。</p>` : '<p class="small muted">現在偵測不到這台電腦上的 Hub。</p>'}
    <label class="row" title="${esc(LAN_HINT)}"><input type="checkbox" id="lan-on" ${s.advertise_url ? 'checked' : ''}/> <b>讓同網段的其他電腦自動找到這台的 Hub</b> <span class="small muted">(?)</span></label>
    <div class="row" style="margin:8px 0 0 24px">
      <input type="text" id="lan-url" value="${esc(url)}" placeholder="http://192.168.x.y:8088" style="flex:1;min-width:240px" title="${esc(LAN_URL_HINT)}" />
      <span class="small muted" title="${esc(LAN_URL_HINT)}">(?)</span>
    </div>
    ${s.lan_ips?.length > 1 ? `<p class="small muted" style="margin:4px 0 0 24px">這台的區網 IP：${s.lan_ips.map(esc).join('、')}</p>` : ''}
    <p class="small" id="lan-state" style="margin:6px 0 0 24px">${advertisingText(s)}</p>
    <p class="small muted" style="margin:6px 0 0 24px">別台電腦連不到這個網址時（例如 Hub 只綁 127.0.0.1），開了也沒用：Hub 的「新增主機」頁會用白話告訴你辦公室的電腦找不找得到它。</p>
    </div>`;
  el.open = wasOpen;
  const on = document.getElementById('lan-on');
  on.onchange = async () => {
    const want = on.checked;
    const u = document.getElementById('lan-url').value.trim();
    if (want && !u) {
      on.checked = false;
      return toast('請先填區網的 Hub 網址');
    }
    on.disabled = true;
    const st = document.getElementById('lan-state');
    st.innerHTML = `<span class="spin"></span> ${want ? '確認這個網址連得到 Hub…' : '關閉中…'}`;
    try {
      const r = await invoke('set_hub_advertise', { url: want ? u : null });
      toast(want ? (r.background_running ? '已開啟：背景自動回報約 1 分鐘內開始廣播' : '已開啟；打開背景自動回報後才會廣播') : '已關閉區網廣播');
      renderLanSection(el);
    } catch (e) {
      on.checked = !want;
      st.innerHTML = `<span style="color:var(--danger)">✗ ${esc(e)}</span>`;
    } finally {
      on.disabled = false;
    }
  };
}

// ---------------- 總覽：上傳到 Hub ----------------
async function renderUploadCard(el) {
  let u;
  try {
    u = await invoke('upload_status');
  } catch {
    el.hidden = true;
    return;
  }
  if (!u.enrolled) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  const failedLater = u.last_error && (!u.last_upload_at || Date.parse(u.last_error_at) > Date.parse(u.last_upload_at));
  el.innerHTML = `<h2>上傳到 Security Hub</h2>
    <div class="row" style="justify-content:space-between">
      <div class="small">
        <div>上次上傳：<b>${u.last_upload_at ? esc(ago(u.last_upload_at)) : '還沒上傳過'}</b></div>
        <div>${u.pending ? `<b style="color:var(--warn)">待重送 ${u.pending} 份報告</b>（連不上 Hub 時暫存，連得上就會自動補送）` : '<span class="muted">沒有待重送的報告</span>'}</div>
        ${failedLater ? `<div style="color:var(--danger)">最近一次上傳失敗（${esc(ago(u.last_error_at))}）：${esc(u.last_error)}</div>` : ''}
      </div>
      <div class="row">
        ${u.pending ? '<button class="btn" data-upload="1" title="先補送暫存的報告，再掃描一次並上傳">重新上傳</button>' : ''}
        <button class="btn primary" data-upload="1" title="現在就完整掃描一次，把結果和連線快照送到 Hub（也會補送暫存的報告）">立即掃描並上傳到 Hub</button>
      </div>
    </div>
    <p class="small muted" id="up-progress" style="margin:8px 0 0"></p>`;
  for (const b of el.querySelectorAll('[data-upload]')) b.onclick = () => uploadNow(el);
}

let uploadBusy = false;
async function uploadNow(card) {
  if (uploadBusy) return;
  uploadBusy = true;
  for (const b of card.querySelectorAll('[data-upload]')) b.disabled = true;
  const p = card.querySelector('#up-progress');
  if (p) p.innerHTML = '<span class="spin"></span> 準備中…';
  const off = await listen('upload-progress', (e) => {
    if (p) p.innerHTML = `<span class="spin"></span> ${esc(e.payload)}`;
  });
  try {
    const r = await invoke('upload_now');
    toast(r.message, 8000);
    if (p) p.textContent = r.message;
  } catch (e) {
    toast(`上傳失敗：${e}`, 8000);
    if (p) p.innerHTML = `<span style="color:var(--danger)">上傳失敗：${esc(e)}</span>`;
  } finally {
    off();
    uploadBusy = false;
    setTimeout(() => renderUploadCard(card), 1500);
  }
}

// ---------------- 尋找同網段的 Hub：結果與說明 ----------------
function hubReach(h) {
  if (h.identity && !h.error) return '<span class="chip ok" title="連得到，而且驗過 Hub 的身分簽章">✓ 連得到</span>';
  return `<span class="chip dangerous" title="${esc(h.error ?? '')}">✗ 連不到</span>${h.error ? `<div class="small muted">${esc(h.error)}</div>` : ''}`;
}

const NO_HUB_HELP = `<div class="small">
  <p><b>沒有找到 Security Hub。</b>常見原因與解法：</p>
  <ol style="margin:4px 0 0 18px;padding:0">
    <li><b>直接問管理員 Hub 的網址</b>，再按上方「輸入 Hub 網址」。</li>
    <li><b>Hub 要讓區網連得到</b>：單機版的 Hub 預設只給它自己那台電腦用（只綁 127.0.0.1），別的電腦連不到也找不到。請管理員改用伺服器版，或在 Hub 的設定加上 AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0。</li>
    <li><b>Hub 跑在 Docker Desktop 裡</b>：它的區網廣播出不了 Docker，要在跑 Hub 的那台電腦打開桌面版「設定 → 讓區網裡的電腦找到這台的 Hub」（或命令列 ai-security-monitor config set hub.advertise_url http://&lt;那台的 IP&gt;:8088）幫忙廣播。跨網段的電腦則要請管理員在公司 DNS 加 _aisecmon._tcp 的 SRV 紀錄。</li>
  </ol>
</div>`;

const ONLY_CONFIG_HELP =
  '<p class="small muted">只找到這台電腦已經加入的 Hub（設定檔）；公司 DNS 和區網廣播都沒有找到它。要讓其他電腦也自動找到，見 Hub「新增主機」頁的「辦公室的電腦找得到這個 Hub 嗎？」。</p>';
