// capture-desktop-screenshots.mjs --frame windows 用的外框：Windows 11 風格的視窗（標題列、最小化／最大化／關閉、圓角、陰影）
// 和主視覺（純漸層桌布＋工作列＋系統匣）。全部用 HTML／SVG 自己畫，沒有 Windows 標誌、沒有微軟桌布或字型檔。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// 全部自己畫：標題列高 32、按鈕寬 46、8px 圓角、柔和陰影；淺色／深色跟著畫面內容。
const APP_ICON = `data:image/png;base64,${fs.readFileSync(path.join(ROOT, 'desktop', 'src-tauri', 'icons', 'icon.png')).toString('base64')}`;
const TITLE = 'AI Security Monitor';
const GLYPH = {
  min: '<svg width="10" height="10" viewBox="0 0 10 10"><path d="M0 5.5h10" stroke="currentColor" stroke-width="1"/></svg>',
  max: '<svg width="10" height="10" viewBox="0 0 10 10"><rect x=".5" y=".5" width="9" height="9" rx="1.5" fill="none" stroke="currentColor" stroke-width="1"/></svg>',
  close: '<svg width="10" height="10" viewBox="0 0 10 10"><path d="M.5.5l9 9M9.5.5l-9 9" stroke="currentColor" stroke-width="1.1"/></svg>',
};
const frameTheme = (dark) =>
  dark
    ? { bar: '#202020', text: '#ffffff', glyph: '#e6e6e6', border: 'rgba(255,255,255,.12)', page: 'linear-gradient(160deg,#252b36,#161a22)' }
    : { bar: '#f3f3f3', text: '#1a1a1a', glyph: '#1a1a1a', border: 'rgba(0,0,0,.18)', page: 'linear-gradient(160deg,#e9edf3,#d3dbe6)' };

const windowHtml = (img, w, h, dark) => {
  const t = frameTheme(dark);
  return `<div class="win" style="width:${w}px;border:1px solid ${t.border};background:${t.bar}">
  <div class="bar" style="background:${t.bar};color:${t.text}">
    <img class="ico" src="${APP_ICON}" alt=""><span class="ttl">${TITLE}</span>
    <span class="caps" style="color:${t.glyph}"><i>${GLYPH.min}</i><i>${GLYPH.max}</i><i>${GLYPH.close}</i></span>
  </div>
  <img class="content" src="${img}" width="${w}" height="${h}" alt="">
</div>`;
};
const FRAME_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;height:100%;overflow:hidden;font-family:"Segoe UI Variable Text","Segoe UI","Microsoft JhengHei",system-ui,sans-serif}
.win{border-radius:8px;overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,.30),0 4px 12px rgba(0,0,0,.16)}
.bar{height:32px;display:flex;align-items:center;user-select:none}
.ico{width:16px;height:16px;margin:0 10px 0 12px}
.ttl{font-size:12px;flex:1;letter-spacing:.1px}
.caps{display:flex;height:32px}
.caps i{width:46px;height:32px;display:flex;align-items:center;justify-content:center}
.content{display:block}
.stage{position:absolute;inset:0;display:flex;align-items:center;justify-content:center}
`;

// 單張：視窗放在中性背景上
export function framedPage(img, w, h, dark) {
  const pad = 44;
  const W = w + 2 + pad * 2;
  const H = h + 32 + 2 + pad * 2;
  const t = frameTheme(dark);
  return { W, H, html: `<!doctype html><meta charset="utf-8"><style>${FRAME_CSS}body{background:${t.page}}</style><div class="stage">${windowHtml(img, w, h, dark)}</div>` };
}

// 主視覺：純漸層桌布＋視窗＋工作列（中間是幾個通用的 app 圖示、右邊是系統匣、時鐘）
export function heroPage(img, w, h, dark) {
  const W = 1920;
  const H = 1080;
  const TB = 48;
  const wall = dark
    ? 'radial-gradient(1200px 800px at 30% 25%,#24476b 0%,transparent 70%),radial-gradient(1000px 700px at 80% 80%,#3a2a5c 0%,transparent 70%),linear-gradient(135deg,#0d1726,#141a2e)'
    : 'radial-gradient(1200px 800px at 25% 20%,#cfe4ff 0%,transparent 70%),radial-gradient(1000px 700px at 85% 85%,#e4d8fb 0%,transparent 70%),linear-gradient(135deg,#a9c8f0,#c7c2ef)';
  const tb = dark ? { bg: 'rgba(28,28,28,.86)', fg: '#ffffff', line: 'rgba(255,255,255,.08)', tile: 'rgba(255,255,255,.07)' } : { bg: 'rgba(238,241,246,.86)', fg: '#1a1a1a', line: 'rgba(0,0,0,.08)', tile: 'rgba(0,0,0,.05)' };
  const fg = tb.fg;
  // 通用圖示：搜尋、資料夾、瀏覽器、終端機（簡單形狀）＋本 app（執行中，下面有指示條）
  const apps = [
    `<svg width="22" height="22" viewBox="0 0 24 24"><circle cx="10" cy="10" r="6.5" fill="none" stroke="${fg}" stroke-width="2"/><path d="M15 15l5.5 5.5" stroke="${fg}" stroke-width="2.2" stroke-linecap="round"/></svg>`,
    `<svg width="26" height="26" viewBox="0 0 24 24"><path d="M2 6.5a2 2 0 012-2h5l2 2h9a2 2 0 012 2V18a2 2 0 01-2 2H4a2 2 0 01-2-2z" fill="#f2b84b"/><path d="M2 9h20v9a2 2 0 01-2 2H4a2 2 0 01-2-2z" fill="#f7cd6b"/></svg>`,
    `<svg width="26" height="26" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#3b82f6"/><path d="M2 12h20M12 2c3 3 3 17 0 20M12 2c-3 3-3 17 0 20" fill="none" stroke="#dbeafe" stroke-width="1.3"/></svg>`,
    `<svg width="26" height="26" viewBox="0 0 24 24"><rect x="2" y="3.5" width="20" height="17" rx="3" fill="#334155"/><path d="M6 9l3.5 3L6 15" fill="none" stroke="#e2e8f0" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M11.5 15.5h6" stroke="#e2e8f0" stroke-width="1.8" stroke-linecap="round"/></svg>`,
  ];
  const tile = (inner, active = false) =>
    `<div style="width:40px;height:40px;border-radius:5px;display:flex;align-items:center;justify-content:center;position:relative;${active ? `background:${tb.tile}` : ''}">${inner}${active ? `<span style="position:absolute;bottom:1px;left:50%;transform:translateX(-50%);width:16px;height:3px;border-radius:2px;background:#4cc2ff"></span>` : ''}</div>`;
  const icons = [...apps.map((a) => tile(a)), tile(`<img src="${APP_ICON}" width="26" height="26" alt="">`, true)].join('');
  const sys = (d) => `<svg width="16" height="16" viewBox="0 0 16 16" style="display:block">${d}</svg>`;
  const wifi = sys(`<path d="M1.5 6a9.5 9.5 0 0113 0M3.8 8.4a6.3 6.3 0 018.4 0M6 10.8a3 3 0 014 0" fill="none" stroke="${fg}" stroke-width="1.3" stroke-linecap="round"/><circle cx="8" cy="13" r="1.1" fill="${fg}"/>`);
  const vol = sys(`<path d="M2 6h2.5L8 3v10L4.5 10H2z" fill="none" stroke="${fg}" stroke-width="1.2" stroke-linejoin="round"/><path d="M10.5 5.5a3.5 3.5 0 010 5M12.5 3.8a6 6 0 010 8.4" fill="none" stroke="${fg}" stroke-width="1.2" stroke-linecap="round"/>`);
  const bat = sys(`<rect x="1" y="4.5" width="12.5" height="7" rx="1.6" fill="none" stroke="${fg}" stroke-width="1.2"/><rect x="2.6" y="6.1" width="7.5" height="3.8" rx=".6" fill="${fg}"/><path d="M15 6.8v2.4" stroke="${fg}" stroke-width="1.3" stroke-linecap="round"/>`);
  const chevron = sys(`<path d="M4 10l4-4 4 4" fill="none" stroke="${fg}" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`);
  const winTop = Math.round((H - TB - (h + 34)) / 2);
  const winLeft = Math.round((W - (w + 2)) / 2);
  const tipBg = dark ? '#2b2b2b' : '#f9f9f9';
  const tipBorder = dark ? 'rgba(255,255,255,.12)' : 'rgba(0,0,0,.12)';
  return {
    W,
    H,
    html: `<!doctype html><meta charset="utf-8"><style>${FRAME_CSS}body{background:${wall}}</style>
<div style="position:absolute;left:${winLeft}px;top:${winTop}px">${windowHtml(img, w, h, dark)}</div>
<div id="tip" style="position:absolute;bottom:${TB + 10}px;padding:5px 9px;font-size:12px;color:${fg};background:${tipBg};border:1px solid ${tipBorder};border-radius:6px;box-shadow:0 4px 14px rgba(0,0,0,.18)">${TITLE}</div>
<div style="position:absolute;left:0;right:0;bottom:0;height:${TB}px;background:${tb.bg};border-top:1px solid ${tb.line};backdrop-filter:blur(30px)">
  <div style="position:absolute;left:50%;top:4px;transform:translateX(-50%);display:flex;gap:4px">${icons}</div>
  <div style="position:absolute;right:12px;top:0;height:${TB}px;display:flex;align-items:center;gap:6px;color:${fg}">
    <div style="padding:8px 6px;border-radius:5px">${chevron}</div>
    <div id="tray" style="padding:7px 6px;border-radius:5px;background:${tb.tile}"><img src="${APP_ICON}" width="18" height="18" style="display:block" alt=""></div>
    <div style="display:flex;gap:9px;padding:8px 9px;border-radius:5px">${wifi}${vol}${bat}</div>
    <div style="padding:4px 8px;text-align:right;font-size:12px;line-height:17px">下午 3:42<br>2026/10/17</div>
  </div>
</div>
<script>{const r=document.getElementById('tray').getBoundingClientRect(),t=document.getElementById('tip');t.style.left=Math.round(Math.min(r.left+r.width/2-t.offsetWidth/2,innerWidth-t.offsetWidth-8))+'px'}</script>`,
  };
}
