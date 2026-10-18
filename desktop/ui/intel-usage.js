// AI Security Monitor 桌面版：情資的使用情境（公司／商業用途、個人／非商業用途）。
// 有些情資來源只准個人或非營利使用（DShield、URLhaus、ThreatFox、AbuseIPDB 免費版…）：只在選「個人／非商業用途」時使用。
// 第一次打開桌面版時問一次（還沒選過＝設定裡沒有 intel.usage），之後在「設定 → 情資來源授權」改。
// 和 app.js 共用 invoke／esc／toast。
'use strict';

const USAGE_HINT =
  '情資來源各有授權：有些只准個人或非營利使用（例如 DShield、URLhaus），公司或營利用途要另外向廠商買授權。選「公司／商業用途」就只用可以商用的來源，大部分來源都可以商用。';

function usageSourceList(sources) {
  return `<ul class="small usage-list">${sources
    .map((s) => `<li><b>${esc(s.vendor)}</b> ${esc(s.name)} <span class="muted">· ${esc(s.license)}${s.lookup ? ' · 需要 API 金鑰' : ''}</span></li>`)
    .join('')}</ul>`;
}

/** 換使用情境；選非商用就順便在背景下載新開的來源。 */
async function setIntelUsage(usage) {
  const r = await invoke('set_intel_usage', { usage });
  if (usage === 'noncommercial') {
    toast('已啟用只限非商業用途的來源，正在背景下載…');
    invoke('intel_update', { force: false })
      .then(() => toast('情資已更新'))
      .catch(() => {});
  } else {
    toast('之後只使用可以商用的情資來源');
  }
  return r;
}

/** 第一次打開：還沒選過使用情境就跳出來問（一定要選一個，之後可以在設定頁改）。 */
async function promptIntelUsageIfNeeded() {
  let info;
  try {
    info = await invoke('intel_usage');
  } catch {
    return;
  }
  if (info.usage) return;
  const n = info.sources.length;
  const box = document.createElement('div');
  box.className = 'overlay';
  box.innerHTML = `<div class="dialog" role="dialog" aria-modal="true" aria-labelledby="iu-title">
    <h2 id="iu-title">這台電腦是公司用，還是個人用？</h2>
    <p class="small">${esc(USAGE_HINT)}</p>
    <div class="choices">
      <button class="choice" data-u="commercial"><b>公司／商業用途</b><span>只用可以商用的情資來源。</span></button>
      <button class="choice" data-u="noncommercial"><b>個人／非商業用途</b><span>另外啟用 ${n} 個只限非商業用途的來源，偵測更完整。</span></button>
    </div>
    <details><summary class="small">只限非商業用途的來源（${n} 個）</summary>${usageSourceList(info.sources)}</details>
    <p class="small muted">之後可以在「設定 → 情資來源授權」改。</p>
  </div>`;
  document.body.appendChild(box);
  const buttons = [...box.querySelectorAll('.choice')];
  buttons[0].focus();
  for (const b of buttons) {
    b.onclick = async () => {
      for (const x of buttons) x.disabled = true;
      try {
        await setIntelUsage(b.dataset.u);
        box.remove();
        if (location.hash.startsWith('#intel') || location.hash.startsWith('#settings')) route();
      } catch (e) {
        toast(String(e), 8000);
        for (const x of buttons) x.disabled = false;
      }
    };
  }
}

/** 設定頁的「情資來源授權」卡。 */
async function renderIntelUsageSection(el) {
  let info;
  try {
    info = await invoke('intel_usage');
  } catch (e) {
    el.innerHTML = `<h2>情資來源授權</h2><p class="small muted">讀取失敗：${esc(e)}</p>`;
    return;
  }
  const n = info.sources.length;
  const radio = (value, title, text) =>
    `<label class="row"><input type="radio" name="intel-usage" value="${value}" ${info.usage === value ? 'checked' : ''} /> <b>${title}</b><span class="small muted">${text}</span></label>`;
  el.innerHTML = `<h2>情資來源授權</h2>
    <p class="small muted" style="margin:0 0 8px">${esc(USAGE_HINT)}</p>
    ${radio('commercial', '公司／商業用途', '：只用可以商用的來源')}
    ${radio('noncommercial', '個人／非商業用途', `：另外使用 ${n} 個只限非商業用途的來源`)}
    ${info.usage ? '' : '<p class="small" style="margin:4px 0 0 24px">還沒選：目前只用可以商用的來源。</p>'}
    <details style="margin-top:6px"><summary class="small">只限非商業用途的來源（${n} 個）</summary>${usageSourceList(info.sources)}</details>
    <p class="small muted" style="margin:6px 0 0">有向廠商買商用授權的話，可以選「個人／非商業用途」來開啟這些來源，不要的再到命令列用 <span class="mono">ai-security-monitor intel disable &lt;id&gt;</span> 關掉。</p>`;
  for (const r of el.querySelectorAll('input[name="intel-usage"]')) {
    r.onchange = async () => {
      for (const x of el.querySelectorAll('input')) x.disabled = true;
      try {
        await setIntelUsage(r.value);
      } catch (e) {
        toast(String(e), 8000);
      }
      renderIntelUsageSection(el);
    };
  }
}

// ---------------- 線上查詢金鑰（威脅情資頁） ----------------
const KEY_SIGNUP = {
  "abuseipdb": "https://www.abuseipdb.com/account/api",
  "crowdsec-cti": "https://app.crowdsec.net/settings/cti-api-keys",
  "greynoise-community": "https://viz.greynoise.io/account/api-key"
};
const PAID_HINT =
  '付費方案和免費版用同一把金鑰、同一個 API（只是額度變大），而且可以商用。勾了之後，這台電腦就算選「公司／商業用途」也會用它查。';

/** 威脅情資頁的「線上查詢金鑰」卡：AbuseIPDB、CrowdSec（可標付費方案）、GreyNoise。 */
async function renderIntelKeys(el) {
  let info;
  try {
    info = await invoke('intel_keys');
  } catch (e) {
    el.innerHTML = `<h2>線上查詢金鑰</h2><p class="small muted">讀取失敗：${esc(e)}</p>`;
    return;
  }
  const row = (p) => {
    const state = !p.has_key
      ? '<span class="chip neutral">沒有金鑰</span>'
      : p.usable
        ? `<span class="chip ok">使用中${p.paid ? '（付費方案）' : ''}</span>`
        : '<a class="chip neutral" href="#settings/intel" title="免費版只限非商業用途；這台電腦選的是公司／商業用途。用付費方案的話勾「付費方案」。">未使用（只限非商用）</a>';
    const paid = p.paid_supported
      ? `<label class="row small" style="white-space:nowrap" title="${esc(PAID_HINT)}"><input type="checkbox" data-paid="${esc(p.id)}" ${p.paid ? 'checked' : ''} ${p.has_key ? '' : 'disabled'} /> 付費方案（可商用） <span class="muted">(?)</span></label>`
      : '<span class="small muted" title="這家的商用版是另一套 API，目前只支援免費版金鑰。">只支援免費版金鑰</span>';
    return `<tr>
      <td><b>${esc(p.vendor)}</b> ${esc(p.name)}<div class="small muted">${esc(p.license)}</div></td>
      <td>${state}</td>
      <td><div class="row"><input type="password" data-key="${esc(p.id)}" placeholder="${p.has_key ? '已設定（輸入新的就換掉）' : '貼上 API 金鑰'}" autocomplete="off" style="min-width:200px" />
        <button class="btn" data-save="${esc(p.id)}">儲存</button>${p.has_key ? `<button class="btn" data-del="${esc(p.id)}">刪除</button>` : ''}
        <a class="link small" data-url="${esc(KEY_SIGNUP[p.id] ?? '')}">申請金鑰</a></div></td>
      <td>${paid}</td>
    </tr>`;
  };
  el.innerHTML = `<h2>線上查詢金鑰（選用）</h2>
    <p class="small muted" style="margin:0 0 8px">掃描時把不認得的公網 IP 拿去這些服務查名聲（每天有額度上限，私有網段一律不送）。金鑰存在這台電腦的密鑰庫，不會上傳到 Hub。</p>
    <label class="row"><input type="checkbox" id="online-lookups" ${info.online_lookups ? 'checked' : ''} /> <b>掃描時線上查詢不認得的公網 IP</b></label>
    <table style="margin-top:8px"><thead><tr><th>服務</th><th>狀態</th><th>金鑰</th><th>方案</th></tr></thead><tbody>${info.providers.map(row).join('')}</tbody></table>
    <p class="small muted" style="margin:8px 0 0">URLhaus、ThreatFox 的商用版是 Spamhaus 另外的 API，DShield 沒有付費金鑰，這幾個目前沒辦法用金鑰改成可商用；說明見 README「公司用還是個人用？」。</p>`;
  const ol = el.querySelector('#online-lookups');
  ol.onchange = async () => {
    try {
      ol.checked = await invoke('set_online_lookups', { enabled: ol.checked });
      toast(ol.checked ? '掃描時會線上查詢' : '已關閉線上查詢');
    } catch (e) {
      toast(String(e), 8000);
    }
  };
  const save = async (id, key, paid) => {
    try {
      await invoke('set_intel_key', { id, key, paid });
      toast(key === '' ? '已刪除金鑰' : '已儲存');
    } catch (e) {
      toast(String(e), 8000);
    }
    renderIntelKeys(el);
  };
  const paidOf = (id) => !!el.querySelector(`[data-paid="${id}"]`)?.checked;
  for (const b of el.querySelectorAll('[data-save]')) {
    b.onclick = () => {
      const id = b.dataset.save;
      const v = el.querySelector(`[data-key="${id}"]`).value.trim();
      if (!v) return toast('先貼上 API 金鑰');
      save(id, v, paidOf(id));
    };
  }
  for (const b of el.querySelectorAll('[data-del]')) b.onclick = () => save(b.dataset.del, '', false);
  for (const c of el.querySelectorAll('[data-paid]')) c.onchange = () => save(c.dataset.paid, null, c.checked);
}
