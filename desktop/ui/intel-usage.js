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
