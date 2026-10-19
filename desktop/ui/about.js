// 「關於 AI Security Monitor」：版本、手動更新、專案連結、作者與授權。
// 資訊層級沿用 DB Kit 的關於對話框；以純 HTML/JS 配合這個桌面版現有架構。
'use strict';

const ABOUT_LINKS = [
  ['⌂', 'GitHub 專案', 'https://github.com/markku636/ai-security-monitor'],
  ['◫', '作者部落格', 'https://blog.markkulab.net/'],
  ['≡', '變更紀錄', 'https://github.com/markku636/ai-security-monitor/blob/main/CHANGELOG.md'],
  ['⚑', '回報問題', 'https://github.com/markku636/ai-security-monitor/issues/new'],
];
const ABOUT_DONATIONS = [
  [5, 'https://www.paypal.com/ncp/payment/8B7GRXA6UJH36'],
  [10, 'https://www.paypal.com/ncp/payment/8LBTFUBBF2CHS'],
  [15, 'https://www.paypal.com/ncp/payment/A653DD46GEU4W'],
  [25, 'https://www.paypal.com/ncp/payment/Y5WPSXVGH3YS4'],
];
const ABOUT_PAYPAL = 'https://paypal.me/226network';
let aboutReturnFocus = null;
let aboutStatus = null;

function aboutPlatform() {
  const p = navigator.userAgentData?.platform || navigator.platform || 'Unknown platform';
  return `${p} · ${navigator.userAgent}`;
}

async function copyAboutVersion() {
  const version = aboutStatus?.current || window.__asmVersion || '版本不明';
  const text = `AI Security Monitor v${version} (${aboutPlatform()})`;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  toast('已複製版本資訊');
}

function renderAboutUpdate(status, phase = 'idle') {
  aboutStatus = status || aboutStatus;
  const box = document.getElementById('about-update');
  if (!box) return;
  const s = aboutStatus;
  if (phase === 'checking') {
    box.innerHTML = '<div class="about-update-state"><span class="spin"></span> 正在檢查更新…</div>';
    return;
  }
  const d = s?.desktop ?? {};
  let state = '';
  if (d.error) state = `<div class="about-update-state err">檢查失敗：${esc(d.error)}</div>`;
  else if (d.available) {
    state = `<button type="button" class="about-new-version" id="about-install">● 有新版 ${esc(d.latest)}，點擊更新</button>`;
  } else if (phase === 'checked' || d.checked_at) {
    state = '<div class="about-update-state ok">已是最新版本</div>';
  } else {
    state = '<div class="about-update-state muted">尚未檢查更新</div>';
  }
  box.innerHTML = `${state}<button type="button" class="btn" id="about-check">檢查更新</button>`;
  document.getElementById('about-check').onclick = checkAboutUpdate;
  const install = document.getElementById('about-install');
  if (install) {
    install.disabled = !!s.blocker;
    install.title = s.blocker || '下載、驗證簽章後安裝，完成後自動重新開啟';
    install.onclick = (e) => installUpdateNow(e.currentTarget);
  }
}

async function checkAboutUpdate() {
  renderAboutUpdate(aboutStatus, 'checking');
  try {
    const s = await invoke('check_updates');
    window.__asmVersion = s.current;
    document.getElementById('about-current-version').textContent = s.current;
    renderAboutUpdate(s, 'checked');
  } catch (e) {
    renderAboutUpdate({ ...(aboutStatus ?? {}), desktop: { error: String(e) } }, 'checked');
  }
}

function closeAbout() {
  const overlay = document.getElementById('about-overlay');
  if (!overlay) return;
  overlay.remove();
  aboutReturnFocus?.focus?.();
  aboutReturnFocus = null;
}

async function openAbout() {
  if (document.getElementById('about-overlay')) return;
  aboutReturnFocus = document.activeElement;
  const overlay = document.createElement('div');
  overlay.id = 'about-overlay';
  overlay.className = 'overlay about-overlay';
  overlay.setAttribute('role', 'presentation');
  overlay.innerHTML = `
    <section class="dialog about-dialog" role="dialog" aria-modal="true" aria-labelledby="about-title">
      <header class="about-head">
        <h2 id="about-title"><span aria-hidden="true">ⓘ</span> 關於 AI Security Monitor</h2>
        <button type="button" class="about-close" id="about-close" aria-label="關閉" title="關閉（Esc）">✕</button>
      </header>
      <div class="about-body">
        <img src="icon.png" alt="AI Security Monitor" class="about-logo" draggable="false" />
        <div class="about-name">AI Security Monitor</div>
        <div class="about-version-line">
          <span>版本 <span id="about-current-version">${esc(aboutStatus?.current ?? window.__asmVersion ?? '讀取中…')}</span></span>
          <button type="button" class="about-copy" id="about-copy" title="複製版本資訊（回報問題時附上）" aria-label="複製版本資訊">▣</button>
        </div>
        <p class="about-description">免費開源的電腦安全檢查工具：監看連線、DNS、漏洞、安全設定與威脅情資。</p>
        <div class="about-update" id="about-update"><div class="about-update-state"><span class="spin"></span> 讀取版本資訊…</div></div>
        <div class="about-links">
          ${ABOUT_LINKS.map(([icon, label, url]) => `<button type="button" class="about-link" data-url="${esc(url)}"><span aria-hidden="true">${icon}</span>${label}</button>`).join('')}
        </div>
        <div class="about-donate">
          <p>這個工具免費且開源。如果它幫你省下時間，可以請我喝杯咖啡。</p>
          <div class="about-donate-actions">
            ${ABOUT_DONATIONS.map(([usd, url]) => `<button type="button" class="donate-btn" data-url="${esc(url)}" title="以 PayPal 贊助 US$${usd}"><span aria-hidden="true">♥</span> $${usd}</button>`).join('')}
            <button type="button" class="about-link" data-url="${ABOUT_PAYPAL}">其他金額</button>
          </div>
        </div>
        <div class="about-license">MIT 授權 · © 2026 mark.ku（markku636）· Tauri + Rust 打造</div>
      </div>
    </section>`;
  document.body.appendChild(overlay);
  document.getElementById('about-close').onclick = closeAbout;
  document.getElementById('about-copy').onclick = copyAboutVersion;
  overlay.onclick = (e) => { if (e.target === overlay) closeAbout(); };
  document.getElementById('about-close').focus();
  try {
    const s = await invoke('update_status');
    if (!document.getElementById('about-overlay')) return;
    aboutStatus = s;
    window.__asmVersion = s.current;
    document.getElementById('about-current-version').textContent = s.current;
    document.getElementById('side-version').textContent = `ai-security-monitor ${s.current}`;
    renderAboutUpdate(s);
  } catch (e) {
    renderAboutUpdate({ desktop: { error: String(e) } });
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.getElementById('about-overlay')) {
    e.preventDefault();
    closeAbout();
  }
});

window.addEventListener('DOMContentLoaded', () => {
  document.getElementById('nav-about').onclick = openAbout;
  document.getElementById('about-version').onclick = openAbout;
  invoke('update_status')
    .then((s) => {
      aboutStatus = s;
      window.__asmVersion = s.current;
      document.getElementById('side-version').textContent = `ai-security-monitor ${s.current}`;
    })
    .catch(() => {});
});
