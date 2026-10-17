// AI Security Monitor 桌面版：設定頁的「公司的 Security Hub」區塊——唯一的加入入口。
// 未加入：自動尋找（公司 DNS、區網廣播）、手動輸入網址、申請加入、註冊金鑰、「先不要」；
// 加入中：等候核准卡片＋輪詢（離開設定頁就停）；被拒絕：說明＋重新尋找；
// 已加入：網址、指紋、開啟 Hub、測試連線、離開，以及「更換 Hub 或重新加入」。
// 和 app.js 共用 invoke／esc／toast／ago（app.js 定義）；這個檔先載入，只定義函式，畫面載入後才執行。
'use strict';

/** 設定頁 Hub 區塊的網址（首次啟動、總覽卡片、舊的 #join 都導到這裡）。 */
const HUB_SECTION = '#settings/hub';

const SOURCE = { explicit: '指定的網址', env: '環境變數', config: '設定檔', dns_srv: '公司 DNS', mdns: '區網廣播' };
const SOURCE_HINT = {
  explicit: '你輸入的網址',
  env: '環境變數 AI_SECURITY_MONITOR_HUB_URL 指定的網址',
  config: '這台電腦已經加入的 Hub（記在設定檔）',
  dns_srv: '公司 DNS 的 _aisecmon._tcp SRV 紀錄（跨網段也找得到）',
  mdns: '同一個網路裡的區網廣播（mDNS，跟印表機被自動找到的原理一樣）',
};
const HUB_HINT = 'Security Hub 是公司（或你自己）架的網站，管理員在上面集中查看每台電腦的安全狀況。加入後，這台電腦會定期把掃描結果回報給它；不加入也能在這台電腦單獨使用。';
const FP_HINT = '指紋是 Hub 的身分證號碼。請和管理員在 Hub「新增主機」頁看到的指紋比對，一樣才是公司的 Hub。';
const CODE_HINT = '管理員在「待核准的主機」清單上會看到同一組核對碼，用來確認是這台電腦。';
const FIND_HINT = '查公司 DNS 與區網廣播，找出辦公室裡的 Hub（約 3–10 秒）。找到的每個 Hub 都會先驗過身分簽章。';
const URL_HINT = '管理員給的 Hub 網址。必須是 https；公司內網（例如 192.168.x.x）或本機可以用 http。';
const KEY_HINT = '註冊金鑰是管理員在 Hub「新增主機」頁建立的一串密碼（asa_ek_ 開頭），用金鑰加入就不必等核准。';
const SKIP_KEY = 'asm.join.skipped';
const NEEDS_CONFIRM = 'needs_confirm:';
const DISCOVERY_TTL = 2 * 60e3;

let joinTimer = null;
let discovery = null; // { at, r }：最近一次尋找的結果，2 分鐘內回到設定頁直接沿用，不重找
let searchSeq = 0;

function stopJoinPoll() {
  clearTimeout(joinTimer);
  joinTimer = null;
}

function joinSkipped() {
  try {
    return localStorage.getItem(SKIP_KEY) === '1';
  } catch {
    return false; // 沒有 localStorage（隱私模式等）就當沒按過「先不要」
  }
}

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

function busy(b, on, label) {
  b.disabled = on;
  if (on) {
    b.dataset.label = b.textContent;
    b.innerHTML = `<span class="spin"></span> ${label}`;
  } else if (b.dataset.label) b.textContent = b.dataset.label;
}

const hubHead = () => `<h2>公司的 Security Hub <span class="muted" title="${esc(HUB_HINT)}">(?)</span></h2>`;
const errLine = (e) => `<span style="color:var(--danger)">✗ ${esc(e)}</span>`;

/** 重新讀 Hub 狀態再畫一次（加入、離開、核准後）。 */
async function refreshHubSection(el, opts = {}) {
  try {
    renderHubSection(el, await invoke('hub_status'), opts);
  } catch (e) {
    if (el.isConnected) el.innerHTML = `${hubHead()}<p class="small">${errLine(e)}</p>`;
  }
}

/**
 * 畫設定頁的 Hub 區塊。st＝hub_status 的回應。
 * opts.search：true＝馬上重新尋找；false＝不自動找；省略＝未加入時自動找（按過「先不要」就只在 opts.focus 時找）。
 * 尋找是非同步的：不會擋住設定頁其他區塊。
 */
function renderHubSection(el, st, opts = {}) {
  stopJoinPoll();
  if (!el?.isConnected) return;
  if (st.pending) return renderHubPending(el, st.pending);
  const joined = !!st.hub_url;
  const autoSearch = opts.search ?? (!joined && (opts.focus === 'hub' || !joinSkipped()));
  const intro = joined
    ? ''
    : '<p class="small" style="margin:0 0 10px">加入後，這台電腦的安全狀況會定期回報到公司的 Hub，由管理員集中查看。不需要金鑰：找到公司的 Hub 後按「申請加入」；Hub 允許自動加入的話馬上完成，否則等管理員核准。</p>';
  const status = joined
    ? `<div class="kv">
        <div>狀態</div><div><span class="chip ok">已加入</span></div>
        <div>Hub 網址</div><div class="mono">${esc(st.hub_url)}</div>
        <div title="${esc(FP_HINT)}">Hub 指紋 (?)</div><div class="mono">${esc(st.hub_fingerprint ?? '—')}</div>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="btn" data-url="${esc(st.hub_url)}" title="在瀏覽器開啟這個 Hub 的網頁">開啟 Security Hub</button>
        <button class="btn" id="hub-test-cur" title="確認目前的 Hub 連得到、是同一個 Hub，並顯示它的版本與指紋">測試連線</button>
        <button class="btn" id="hub-leave" title="這台電腦不再回報給這個 Hub">離開這個 Hub</button>
      </div>
      <div id="hub-cur-result" class="small" style="margin-top:8px"></div>`
    : '<div class="kv"><div>狀態</div><div>未加入（只在這台電腦使用）</div></div>';
  const form = `
    <h3 class="sub-h">找到的 Hub</h3>
    <div id="join-found"></div>
    <div class="row" style="margin-top:8px"><button class="btn" id="join-search" title="${esc(FIND_HINT)}">尋找公司的 Hub</button></div>
    <h3 class="sub-h">或輸入管理員給的 Hub 網址</h3>
    <div class="row">
      <input type="text" id="hub-url" placeholder="https://hub.example.com" value="${esc(st.hub_url ?? '')}" style="flex:1;min-width:240px" title="${esc(URL_HINT)}" />
      <button class="btn" id="hub-test" title="確認這個網址連得到、是 Security Hub，並顯示它的版本與指紋">測試這個網址</button>
      <button class="btn primary" id="hub-join" title="不需要金鑰：送出加入申請；Hub 允許自動加入就馬上完成，否則等管理員核准">申請加入</button>
    </div>
    <div id="hub-result" class="small" style="margin-top:8px"></div>
    <details style="margin-top:10px"><summary class="small">我有註冊金鑰（進階） <span class="muted" title="${esc(KEY_HINT)}">(?)</span></summary>
      <p class="small muted">管理員也可以在 Hub「新增主機」頁建立註冊金鑰（asa_ek_…）給你，用金鑰加入就不必等核准。網址填在上面的欄位。</p>
      <div class="row"><input type="text" id="hub-key" placeholder="asa_ek_…" style="flex:1;min-width:240px" autocomplete="off" spellcheck="false" /><button class="btn" id="hub-key-go">用金鑰加入</button></div>
    </details>`;
  el.innerHTML = `${hubHead()}${intro}${status}
    ${joined ? `<details id="hub-change" class="sub-section"${opts.search ? ' open' : ''}><summary><b>更換 Hub 或重新加入</b></summary>${form}</details>` : form}
    ${!joined && !joinSkipped() ? `<p class="small muted" style="margin:12px 0 0"><a class="link" href="#overview" id="join-skip">先不要，只在這台電腦使用</a></p>` : ''}`;
  bindHubForm(el);
  if (joined) bindJoined(el, st);
  const skip = el.querySelector('#join-skip');
  if (skip) {
    skip.onclick = () => {
      try {
        localStorage.setItem(SKIP_KEY, '1');
      } catch {
        // 存不了也沒關係：只是下次開啟時還會再帶到這裡
      }
    };
  }
  const fresh = discovery && Date.now() - discovery.at < DISCOVERY_TTL;
  if (opts.search === true || (autoSearch && !fresh)) searchHubs(el);
  else if (fresh) showHubs(el, discovery.r);
  else el.querySelector('#join-found').innerHTML = '<p class="muted small">按「尋找公司的 Hub」開始。</p>';
}

function bindJoined(el, st) {
  const res = el.querySelector('#hub-cur-result');
  el.querySelector('#hub-test-cur').onclick = (ev) => testHub(ev.currentTarget, st.hub_url, res);
  el.querySelector('#hub-leave').onclick = async () => {
    if (!window.confirm('離開這個 Hub？\n\n這台電腦會停止回報、刪除這台保存的 Hub 金鑰。Hub 上這台主機的紀錄不會自動刪除，需要的話請管理員在 Hub 的「主機」頁刪除。')) return;
    try {
      await invoke('leave_hub');
      toast('已離開 Hub');
      discovery = null;
      refreshHubSection(el, { search: false });
    } catch (e) {
      toast(String(e), 8000);
    }
  };
}

function bindHubForm(el) {
  const res = el.querySelector('#hub-result');
  const url = () => el.querySelector('#hub-url').value.trim();
  el.querySelector('#join-search').onclick = () => searchHubs(el);
  el.querySelector('#hub-test').onclick = (ev) => {
    if (!url()) return toast('請先輸入 Hub 網址');
    testHub(ev.currentTarget, url(), res);
  };
  el.querySelector('#hub-join').onclick = async (ev) => {
    if (!url()) return toast('請先輸入 Hub 網址，或按「尋找公司的 Hub」');
    const b = ev.currentTarget;
    busy(b, true, '確認 Hub…');
    try {
      const c = await invoke('hub_check', { url: url() });
      if (!c.identity) throw new Error('這個 Hub 版本較舊，不支援免金鑰加入；請用註冊金鑰');
      if (!window.confirm(`申請加入「${c.identity.name}」？\n網址：${c.url}\n指紋：${c.identity.fingerprint}\n\n請確認指紋和管理員給的一樣。`)) return;
      const r = await invokeConfirmed('request_join', { url: c.url, fingerprint: c.identity.fingerprint });
      if (r) afterJoinRequest(el, r);
    } catch (e) {
      res.innerHTML = errLine(e);
    } finally {
      if (b.isConnected) busy(b, false);
    }
  };
  el.querySelector('#hub-key-go').onclick = async (ev) => {
    const key = el.querySelector('#hub-key').value.trim();
    if (!url() || !key) return toast('請輸入 Hub 網址與註冊金鑰');
    const b = ev.currentTarget;
    busy(b, true, '加入中…');
    try {
      const r = await invokeConfirmed('enroll_with_key', { url: url(), key });
      if (r) {
        toast('已用金鑰加入 Hub');
        discovery = null;
        renderHubSection(el, r, { search: false });
      }
    } catch (e) {
      res.innerHTML = errLine(e);
    } finally {
      if (b.isConnected) busy(b, false);
    }
  };
}

/** 申請送出後：改畫等候卡片並開始確認（自動允許加入的 Hub 第一次確認就完成）。 */
function afterJoinRequest(el, pending) {
  discovery = null;
  renderHubPending(el, pending);
}

async function testHub(b, u, res) {
  busy(b, true, '測試中…');
  try {
    const c = await invoke('hub_check', { url: u });
    const id = c.identity;
    res.innerHTML = `✓ 連得到 <span class="mono">${esc(c.url)}</span>：${esc(id?.name ?? 'Security Hub')} ${esc(c.health?.version ?? '')}
      ${id ? `・指紋 <span class="mono">${esc(id.fingerprint)}</span>` : '・這個 Hub 版本較舊，沒有身分指紋（只能用註冊金鑰加入）'}
      ${c.fingerprint_changed ? '<br><b style="color:var(--danger)">注意：這個 Hub 的指紋和這台電腦目前加入的不同。可能是另一個 Hub，或 Hub 重新安裝過；請先和管理員確認。</b>' : ''}`;
  } catch (e) {
    res.innerHTML = errLine(e);
  } finally {
    if (b.isConnected) busy(b, false);
  }
}

// ---------------- 尋找 ----------------
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
        <td><span class="chip neutral" title="${esc(SOURCE_HINT[h.source] ?? '')}">${esc(SOURCE[h.source] ?? h.source)}</span>${h.detail ? `<div class="small muted">${esc(h.detail)}</div>` : ''}</td>
        <td>${hubReach(h)}</td>
        <td class="mono" title="${esc(FP_HINT)}">${esc(id?.fingerprint ?? '—')}${pin ? ' <span class="chip ok">這台記得的</span>' : ''}</td>
        <td>${ok ? `<button class="btn primary" data-join="${i}">${pin ? '重新加入' : '申請加入'}</button>` : h.error ? '' : `<span class="small muted">${esc(why)}</span>`}</td>
      </tr>`;
    })
    .join('');
}

async function searchHubs(el) {
  const box = el.querySelector('#join-found');
  const btn = el.querySelector('#join-search');
  if (!box) return;
  const seq = ++searchSeq;
  box.innerHTML = '<p class="muted small"><span class="spin"></span> 正在尋找（公司 DNS、區網廣播），約 3–10 秒…</p>';
  if (btn) btn.disabled = true;
  try {
    const r = await invoke('discover_hubs', { url: null });
    discovery = { at: Date.now(), r };
    if (seq === searchSeq && box.isConnected) showHubs(el, r);
  } catch (e) {
    if (seq === searchSeq && box.isConnected) box.innerHTML = `<p class="small">尋找失敗：${esc(e)}</p>`;
  } finally {
    if (btn?.isConnected) {
      btn.disabled = false;
      btn.textContent = '重新尋找';
    }
  }
}

function showHubs(el, r) {
  const box = el.querySelector('#join-found');
  if (!box) return;
  const btn = el.querySelector('#join-search');
  if (btn) btn.textContent = '重新尋找';
  if (!r.hubs.length) {
    box.innerHTML = NO_HUB_HELP;
    return;
  }
  const onlyConfig = r.hubs.every((h) => h.source === 'config');
  const when = discovery?.r === r && Date.now() - discovery.at > 30e3 ? `<span class="small muted">（${esc(ago(new Date(discovery.at).toISOString()))}找的）</span>` : '';
  box.innerHTML = `<table><thead><tr><th>Hub</th><th>找到的方式</th><th>連線</th><th title="${esc(FP_HINT)}">指紋 (?)</th><th></th></tr></thead><tbody>${hubRows(r.hubs, r.pinned_fingerprint)}</tbody></table>
    <p class="small muted">找到好幾個時，請先問管理員公司的 Hub 指紋是哪一個。${when}</p>${onlyConfig ? ONLY_CONFIG_HELP : ''}${r.hubs.some((h) => h.identity && !h.error) ? '' : NO_HUB_HELP}`;
  for (const b of box.querySelectorAll('[data-join]')) {
    b.onclick = async () => {
      const h = r.hubs[Number(b.dataset.join)];
      if (!window.confirm(`申請加入「${h.identity.name}」？\n網址：${h.url}\n指紋：${h.identity.fingerprint}\n\n請確認指紋和管理員給的一樣。`)) return;
      b.disabled = true;
      try {
        const p = await invokeConfirmed('request_join', { url: h.url, fingerprint: h.identity.fingerprint });
        if (p) afterJoinRequest(el, p);
        else b.disabled = false;
      } catch (e) {
        toast(String(e), 8000);
        b.disabled = false;
      }
    };
  }
}

// ---------------- 等候核准 ----------------
function renderHubPending(el, p) {
  // Hub 是「自動允許加入」模式時申請一送出就核准了，這段只會閃一下
  const auto = p.status === 'approved';
  el.innerHTML = `${hubHead()}
    <div class="kv">
      <div>狀態</div><div><span class="chip ${auto ? 'ok' : 'medium'}">${auto ? 'Hub 已允許加入，正在完成…' : '等候管理員核准'}</span></div>
      <div>申請加入</div><div><b>${esc(p.hub_name)}</b> <span class="mono">${esc(p.hub_url)}</span></div>
      <div title="${esc(FP_HINT)}">Hub 指紋 (?)</div><div class="mono">${esc(p.hub_fingerprint)}</div>
      <div title="${esc(CODE_HINT)}">這台電腦的核對碼 (?)</div><div class="mono" style="font-size:16px">${esc(p.request_code)}</div>
      <div>送出時間</div><div>${esc(ago(p.created_at))}</div>
    </div>
    ${auto ? '' : '<p class="small" style="margin:10px 0 0">請管理員到 Hub 的「新增主機 → 待核准的主機」核對上面的指紋與核對碼後按「核准」。</p>'}
    <p class="small muted" id="join-state" style="margin:8px 0"><span class="spin"></span> 等候中，會自動確認…（關掉視窗也沒關係，背景服務會繼續等）</p>
    <div class="row"><button class="btn" id="join-check">現在確認</button><button class="btn" id="join-cancel">取消申請</button></div>`;
  el.querySelector('#join-check').onclick = () => pollJoin(el, false);
  el.querySelector('#join-cancel').onclick = async () => {
    if (!window.confirm('取消這次的加入申請？')) return;
    stopJoinPoll();
    try {
      await invoke('cancel_join');
    } catch (e) {
      toast(String(e), 8000);
    }
    refreshHubSection(el, { search: true });
  };
  pollJoin(el, true);
}

async function pollJoin(el, quiet) {
  stopJoinPoll();
  // 只在設定頁還開著、這個區塊還在畫面上時繼續確認（換頁時 route() 也會停）
  const live = () => el.isConnected && location.hash.startsWith('#settings');
  const again = (ms) => {
    if (live()) joinTimer = setTimeout(() => pollJoin(el, true), ms);
  };
  const state = () => el.querySelector('#join-state');
  try {
    const r = await invoke('join_poll');
    if (r.status === 'approved') {
      toast(`加入完成：已加入 ${r.hub_name}`);
      if (live()) refreshHubSection(el, { search: false });
      return;
    }
    if (!live()) return;
    if (r.status === 'rejected') {
      el.innerHTML = `${hubHead()}
        <div class="kv"><div>狀態</div><div><span class="chip dangerous">申請被拒絕</span></div></div>
        <p class="small">管理員拒絕了這台電腦的加入申請${r.reason ? `：${esc(r.reason)}` : ''}。如有疑問請聯絡管理員。</p>
        <div class="row"><button class="btn" id="join-again" title="${esc(FIND_HINT)}">重新尋找</button></div>`;
      el.querySelector('#join-again').onclick = () => refreshHubSection(el, { search: true });
      return;
    }
    if (r.status === 'expired' || r.status === 'none') {
      toast('加入申請已過期或被刪除，請重新申請');
      refreshHubSection(el, { search: true });
      return;
    }
    if (!quiet && state()) state().innerHTML = '<span class="spin"></span> 還沒核准，稍後會再自動確認…';
    again(Math.max(5, r.poll_interval_s || 15) * 1000);
  } catch (e) {
    if (!live()) return;
    if (state()) state().textContent = `確認失敗：${e}（稍後重試）`;
    again(30000);
  }
}
