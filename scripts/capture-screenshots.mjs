// README 截圖：用無頭 Chrome／Edge（CDP，帶 Authorization 標頭）擷取 Security Hub 各頁。
//   node scripts/capture-screenshots.mjs --hub http://127.0.0.1:3000 --admin <secret> [--out docs/images] [--browser <path>]
// 建議先用 scripts/demo-seed.mjs 灌示範資料，別把真實主機資料放進公開的截圖。
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const HUB = (args.hub ?? 'http://127.0.0.1:3000').replace(/\/$/, '');
const ADMIN = args.admin ?? process.env.AI_SECURITY_MONITOR_HUB_ADMIN_SECRET ?? process.env.ASA_HUB_ADMIN_SECRET;
const OUT = path.resolve(args.out ?? 'docs/images');
if (!ADMIN) {
  console.error('usage: node scripts/capture-screenshots.mjs --hub <url> --admin <secret> [--out dir]');
  process.exit(2);
}

function findBrowser() {
  const candidates = [
    args.browser,
    process.env.CHROME_PATH,
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/microsoft-edge',
  ];
  return candidates.find((p) => p && fs.existsSync(p));
}

// 名稱｜路徑｜寬度｜深色
const PAGES = [
  ['overview', '/', 1440],
  ['agent', '/agents/AGENT_FIN', 1440],
  ['agent-server', '/agents/AGENT_DC', 1440],
  ['connections', '/connections', 1440],
  ['findings', '/findings', 1440],
  ['vulns', '/vulns', 1440],
  ['hardening', '/hardening', 1440],
  ['events', '/events', 1440],
  ['intel', '/intel', 1440],
  ['install', '/install', 1440],
  ['overview-dark', '/', 1440, true],
  ['agent-hardening-dark', '/agents/AGENT_FIN?tab=hardening&show=all', 1440, true],
  ['overview-mobile', '/', 390],
];

const browser = findBrowser();
if (!browser) {
  console.error('Chrome or Edge not found; pass --browser <path>');
  process.exit(1);
}
fs.mkdirSync(OUT, { recursive: true });

// 找 fin-laptop-07 的 agent id（示範資料）
const agents = await (await fetch(`${HUB}/api/v1/agents`, { headers: { authorization: `Bearer ${ADMIN}` } })).json();
const list = agents.items ?? agents;
const fin = list.find?.((a) => a.hostname === 'fin-laptop-07') ?? list[0];
// Windows Server 網域控制站（示範資料）
const dc = list.find?.((a) => a.hostname === 'dc-01') ?? fin;

const port = 9300 + Math.floor(Math.random() * 500);
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-security-monitor-shot-'));
const proc = spawn(browser, ['--headless=new', '--disable-gpu', '--hide-scrollbars', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 60 && !target; i++) {
  await sleep(250);
  try {
    target = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((x) => x.type === 'page');
  } catch {
    // 還沒起來
  }
}
if (!target) throw new Error('browser did not start');
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let seq = 0;
const pending = new Map();
const listeners = [];
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  } else if (m.method) {
    for (const l of listeners.splice(0)) l(m);
  }
});
const send = (method, params = {}) =>
  new Promise((r) => {
    const i = ++seq;
    pending.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const once = (name) =>
  new Promise((r) => {
    const f = (m) => (m.method === name ? r(m) : listeners.push(f));
    listeners.push(f);
  });

await send('Page.enable');
await send('Network.enable');
await send('Network.setExtraHTTPHeaders', { headers: { authorization: `Bearer ${ADMIN}` } });
for (const [name, p, width, dark] of PAGES) {
  const url = HUB + p.replace('AGENT_FIN', encodeURIComponent(fin?.id ?? '')).replace('AGENT_DC', encodeURIComponent(dc?.id ?? ''));
  const mobile = width < 600;
  await send('Emulation.setDeviceMetricsOverride', { width, height: mobile ? 844 : 900, deviceScaleFactor: 1, mobile });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }] });
  const loaded = once('Page.loadEventFired');
  await send('Page.navigate', { url });
  await loaded;
  await sleep(500);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, `${name}.png`), Buffer.from(shot.result.data, 'base64'));
  console.log(`${name}.png`);
}
ws.close();
proc.kill();
