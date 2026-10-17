// README 截圖（桌面版）：在本機用靜態伺服器提供 desktop/ui，注入假的 window.__TAURI__（示範資料），
// 再用無頭 Chrome／Edge（CDP）擷取各頁。完全不碰真實設定目錄、不跑真的掃描、不呼叫 AI。
//   node scripts/capture-desktop-screenshots.mjs [--out docs/images] [--browser <path>] [--only desktop-overview,…]
//   node scripts/capture-desktop-screenshots.mjs --frame windows
//     → 改輸出 windows-desktop-*.png：把畫面套上 Windows 11 風格的視窗外框（標題列、最小化／最大化／關閉、圓角、陰影），
//       另外產生 windows-desktop-hero(-dark).png：視窗放在純漸層桌布上，下方有工作列與系統匣圖示。
//       外框、工作列、圖示全部用 HTML／SVG 自己畫（沒有 Windows 標誌、沒有微軟桌布）。
// 示範資料和 scripts/demo-seed.mjs 的 fin-laptop-07 一致：虛構主機、文件保留網段 IP（RFC 5737）、example.com 網域。
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { framedPage, heroPage } from './windows-frame.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UI = path.join(ROOT, 'desktop', 'ui');
const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const OUT = path.resolve(args.out ?? path.join(ROOT, 'docs', 'images'));
const FRAME = args.frame ?? null;
if (FRAME && FRAME !== 'windows') {
  console.error(`unknown --frame ${FRAME} (supported: windows)`);
  process.exit(1);
}
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'desktop', 'src-tauri', 'tauri.conf.json'), 'utf8')).version;

// ---------------- 示範資料 ----------------
const now = Date.now();
const iso = (minsAgo) => new Date(now - minsAgo * 60_000).toISOString();

const FEEDS = {
  feodo: { feed_id: 'abusech-feodo', vendor: 'abuse.ch', name: 'Feodo Tracker (recommended)', confidence: 90, license: 'CC0 1.0', source_url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt' },
  cins: { feed_id: 'cins-army', vendor: 'CINS / Sentinel IPS', name: 'CINS Army list', confidence: 75, license: 'Free for use (see site)', source_url: 'https://cinsscore.com/list/ci-badguys.txt' },
  blocklistde: { feed_id: 'blocklist-de-all', vendor: 'blocklist.de', name: 'blocklist.de all', confidence: 80, license: 'Free (fail2ban community reports)', source_url: 'https://lists.blocklist.de/lists/all.txt' },
};
const hit = (k, ip) => ({ ...FEEDS[k], matched: ip, fetched_at: iso(12) });

const LOCAL = '192.0.2.77';
let lp = 52100;
const conn = (c) => ({
  proto: 'tcp',
  local_ip: LOCAL,
  local_port: lp++,
  state: 'ESTABLISHED',
  direction: 'outbound',
  ...c,
});
const UPDATER = { pid: 4242, name: 'updater.exe', exe: 'C:\\Users\\demo\\AppData\\Local\\Temp\\updater.exe' };
const CONNECTIONS = [
  ...[0, 1].map(() =>
    conn({
      remote_ip: '203.0.113.66',
      remote_port: 443,
      process: UPDATER,
      geo: { country: 'NL', asn: 64500, org: 'Example Hosting' },
      verdict: { level: 'dangerous', reasons: [{ type: 'intel_hit', ...hit('feodo', '203.0.113.66') }, { type: 'anomaly', kind: 'temp_dir_process', detail: UPDATER.exe }] },
    }),
  ),
  conn({
    remote_ip: '198.51.100.80',
    remote_port: 8443,
    process: { pid: 5120, name: 'powershell.exe' },
    geo: { country: 'SG', asn: 64511, org: 'Example VPS' },
    verdict: { level: 'suspicious', reasons: [{ type: 'intel_hit', ...hit('cins', '198.51.100.80') }, { type: 'anomaly', kind: 'shell_with_network', detail: 'powershell.exe' }] },
  }),
  conn({
    remote_ip: '198.51.100.140',
    remote_port: 4444,
    process: { pid: 6312, name: 'syncagent.exe' },
    geo: { country: 'DE', asn: 64502, org: 'Example Cloud' },
    verdict: { level: 'suspicious', reasons: [{ type: 'anomaly', kind: 'beaconing', detail: '每 60 秒一次，連續 42 次' }, { type: 'anomaly', kind: 'risky_port', detail: '4444' }] },
  }),
  conn({
    direction: 'inbound',
    local_port: 3389,
    remote_ip: '198.51.100.23',
    remote_port: 51522,
    process: { pid: 1180, name: 'svchost.exe' },
    geo: { country: 'RU', asn: 64503, org: 'Example Transit' },
    verdict: { level: 'suspicious', reasons: [{ type: 'intel_hit', ...hit('blocklistde', '198.51.100.23') }, { type: 'anomaly', kind: 'failed_logon_burst_source', detail: '10 分鐘內 96 次登入失敗' }] },
  }),
  ...[0, 1, 2, 3].map(() =>
    conn({ remote_ip: '203.0.113.20', remote_port: 443, process: { pid: 7712, name: 'msedge.exe' }, geo: { country: 'US', asn: 64496, org: 'Example CDN' }, verdict: { level: 'safe', reasons: [{ type: 'known_good', list: 'cdn', detail: 'Example CDN' }] } }),
  ),
  conn({ remote_ip: '203.0.113.30', remote_port: 443, process: { pid: 6020, name: 'Teams.exe' }, geo: { country: 'US', asn: 64497, org: 'Example SaaS' }, verdict: { level: 'unknown', reasons: [] } }),
  conn({ remote_ip: '203.0.113.31', remote_port: 443, process: { pid: 6020, name: 'Teams.exe' }, geo: { country: 'US', asn: 64497, org: 'Example SaaS' }, verdict: { level: 'unknown', reasons: [] } }),
  conn({ remote_ip: '203.0.113.45', remote_port: 443, process: { pid: 8840, name: 'OneDrive.exe' }, geo: { country: 'US', asn: 64498, org: 'Example Storage' }, verdict: { level: 'safe', reasons: [{ type: 'known_good', list: 'saas', detail: 'Example Storage' }] } }),
  conn({ remote_ip: '192.0.2.1', remote_port: 53, proto: 'udp', state: 'NONE', process: { pid: 2280, name: 'svchost.exe' }, verdict: { level: 'safe', reasons: [{ type: 'private_network' }] } }),
  conn({ direction: 'listening', local_ip: '0.0.0.0', local_port: 445, remote_ip: null, remote_port: null, state: 'LISTEN', process: { pid: 4, name: 'System' }, verdict: { level: 'unknown', reasons: [{ type: 'anomaly', kind: 'exposed_listener', detail: '0.0.0.0:445' }] } }),
  conn({ direction: 'listening', local_ip: '127.0.0.1', local_port: 7869, remote_ip: null, remote_port: null, state: 'LISTEN', process: { pid: 9120, name: 'node.exe' }, verdict: { level: 'safe', reasons: [{ type: 'loopback' }] } }),
];

const f = (o) => ({ detail: '', recommendation: '', intel_hits: [], ...o });
const FINDINGS = [
  f({ scanner: 'intel', rule: 'intel.outbound_match', severity: 'critical', title: '連到威脅情資列名的 IP：203.0.113.66', detail: 'updater.exe（暫存目錄）↔ 203.0.113.66:443（判定：危險）。來源：abuse.ch Feodo Tracker（CC0 1.0，90%）', recommendation: '隔離主機、結束 updater.exe、封鎖 203.0.113.66，並用防毒完整掃描。', intel_hits: [hit('feodo', '203.0.113.66')] }),
  f({ scanner: 'vuln', rule: 'vuln.app.7zip-cve-2025-0411', severity: 'critical', title: '7-Zip 24.08 (x64) 有已知漏洞（CVE-2025-0411）', detail: 'Mark-of-the-Web bypass，已遭實際利用（CISA KEV）。', recommendation: '更新 7-Zip 到 24.09 以上。' }),
  f({ scanner: 'hardening', rule: 'hardening.win.bitlocker.system', severity: 'high', title: '未通過：系統磁碟已用 BitLocker／裝置加密保護', detail: '目前值 off，期望 on。筆電遺失時資料可被直接讀出。', recommendation: '設定 → 隱私權與安全性 → 裝置加密。' }),
  f({ scanner: 'events', rule: 'events.bugcheck', severity: 'high', title: '藍屏 0x00000124 WHEA_UNCORRECTABLE_ERROR', detail: '1 天前。可能原因：CPU 或記憶體硬體錯誤、超頻或電壓不穩。', recommendation: '還原 BIOS 預設（關超頻）、更新 BIOS 與晶片組驅動、跑記憶體測試。' }),
  f({ scanner: 'connections', rule: 'connections.shell_with_network', severity: 'medium', title: 'powershell.exe 連到情資列名的 IP：198.51.100.80:8443', detail: '命令列程式直接連外，且對方列在 CINS Army list（75%）。', recommendation: '確認是不是自己或 IT 執行的腳本；不是就結束行程並封鎖該 IP。', intel_hits: [hit('cins', '198.51.100.80')] }),
  f({ scanner: 'connections', rule: 'connections.beaconing', severity: 'medium', title: 'syncagent.exe 每 60 秒連一次 198.51.100.140:4444', detail: '週期非常規律（連續 42 次），像是遠端控制程式的回報（beacon）。', recommendation: '確認這個程式的來源；不認得就移除並封鎖目的地。' }),
  f({ scanner: 'vuln', rule: 'vuln.os_eol_soon', severity: 'medium', title: 'Windows 11 23H2 支援將在 24 天後結束', recommendation: '升級到 Windows 11 24H2 或更新版本。' }),
  f({ scanner: 'vuln', rule: 'vuln.updates_stale', severity: 'medium', title: 'Windows 已經 52 天沒有安裝更新', detail: '最後一次更新 KB5044285。', recommendation: '設定 → Windows Update → 檢查更新。' }),
  f({ scanner: 'hardening', rule: 'hardening.win.lsa.protection', severity: 'medium', title: '未通過：LSA 保護（RunAsPPL）已開啟', recommendation: 'Windows 安全性 → 裝置安全性 → 核心隔離 → 本機安全性授權保護。' }),
  f({ scanner: 'hardening', rule: 'hardening.win.llmnr.disabled', severity: 'low', title: '未通過：LLMNR 名稱解析已關閉', recommendation: '群組原則「關閉多點傳送名稱解析」。' }),
  f({ scanner: 'hardening', rule: 'hardening.win.autorun.disabled', severity: 'low', title: '未通過：所有磁碟機的自動執行（AutoRun）已關閉', recommendation: 'NoDriveTypeAutoRun=255。' }),
  f({ scanner: 'vuln', rule: 'vuln.app.python-eol', severity: 'low', title: 'Python 3.10.11 已停止安全性更新', recommendation: '安裝仍受支援的 Python 版本並移除 3.10。' }),
  f({ scanner: 'ports', rule: 'ports.exposed_filtered', severity: 'info', title: '445/tcp（System）對所有介面監聽，但防火牆擋住外部連入', recommendation: '不需要檔案分享時可關閉。' }),
];
const counts = Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, FINDINGS.filter((x) => x.severity === s).length]));
const SCORE = { overall: 38, connections: 25, exposure: 90, vulns: 40, hardening: 62 };
const REPORT = { schema_version: 1, finished_at: iso(4), started_at: iso(5), score: SCORE, partial: true, agent: { hostname: 'fin-laptop-07' }, findings: FINDINGS };

// 情資：來源清單取自 feeds/registry.json（和 agent 一樣過濾掉線上查詢類），筆數與時間是示範值
const registry = JSON.parse(fs.readFileSync(path.join(ROOT, 'feeds', 'registry.json'), 'utf8'));
const DEMO_ENTRIES = { 'spamhaus-drop-v4': 1462, 'spamhaus-drop-v6': 92, 'spamhaus-asndrop': 431, 'abusech-feodo': 318, 'abusech-urlhaus-hosts': 2874, 'abusech-threatfox-ipport': 5120, 'blocklist-de-all': 21384, 'blocklist-de-ssh': 6610, 'blocklist-de-bruteforcelogin': 1904, 'cins-army': 15000, 'et-compromised': 512, 'et-block': 0, 'dshield-block': 20, 'tor-exits': 1268, ipsum: 98211, 'firehol-level1': 4532, 'dbip-country-lite': 652310, 'dbip-asn-lite': 512004, 'cisa-kev': 1384 };
const INTEL_FEEDS = registry.feeds
  .filter((x) => x.format !== 'lookup-api' && (x.urls ?? []).length)
  .map((x, i) => {
    const enabled = x.enabled_default !== false;
    return {
      id: x.id,
      name: x.name,
      vendor: x.vendor,
      kind: x.kind,
      enabled,
      license: x.license?.name ?? '',
      source_url: x.urls[0],
      entries: enabled ? DEMO_ENTRIES[x.id] ?? 1000 + i * 37 : 0,
      fetched_at: enabled ? iso(12 + (i % 4) * 9) : null,
      checked_at: enabled ? iso(12) : null,
      status: enabled ? 'ok' : 'never',
      error: null,
      from_hub: enabled,
    };
  });
const enabledFeeds = INTEL_FEEDS.filter((x) => x.enabled).length;

const OVERVIEW = {
  version: VERSION,
  agent_id: '7c1e9a40-2b6d-4f83-9e21-5d0a8b3f6c17',
  hostname: 'fin-laptop-07',
  config_dir: 'C:\\Users\\demo\\AppData\\Roaming\\ai-security-monitor',
  hub_url: 'https://hub.example.com',
  report: { finished_at: REPORT.finished_at, score: SCORE, counts, findings: FINDINGS.length, partial: true, hostname: 'fin-laptop-07' },
  intel: { checked_at: iso(12), ok: enabledFeeds, total: enabledFeeds, source: 'hub' },
  watcher_running: true,
  elevated: false,
  metrics: { performance: true, interval: '1m' },
};

// 最近 1 小時的流量／效能（背景服務每分鐘一個樣本）：辦公時段的起伏、最後幾分鐘 updater.exe 往外傳
const MB = 1024 * 1024;
const GB = 1024 * MB;
const wave = (i, k) => 0.8 + 0.35 * Math.sin(i / 6 + k) + 0.15 * Math.sin(i / 2.3 + k * 3);
const METRIC_POINTS = Array.from({ length: 60 }, (_, k) => {
  const i = 59 - k;
  const upload = i < 6 ? 5.8 * MB : 0;
  return {
    ts: iso(i),
    rx: Math.round(1.1 * MB * wave(k, 1)),
    tx: Math.round(0.18 * MB * wave(k, 2) + upload),
    cpu: i < 6 ? 88 + 6 * wave(k, 3) / 1.3 : 16 + 9 * wave(k, 3),
    mem: 68 + 4 * wave(k, 4),
    disk: 71,
  };
});
const last = METRIC_POINTS[METRIC_POINTS.length - 1];
const METRICS = {
  performance_enabled: true,
  interval: '1m',
  source: 'background',
  points: METRIC_POINTS,
  current: {
    ts: last.ts,
    interval_s: 60,
    net: { rx_bytes: last.rx * 60, tx_bytes: last.tx * 60, interfaces: [{ name: 'Wi-Fi', virtual: false, rx_bytes: last.rx * 60, tx_bytes: last.tx * 60 }] },
    perf: {
      cpu_pct: Math.round(last.cpu * 10) / 10,
      cpu_cores: 12,
      mem_used: Math.round(16 * GB * (last.mem / 100)),
      mem_total: 16 * GB,
      swap_used: 1.2 * GB,
      swap_total: 5 * GB,
      disks: [{ mount: 'C:\\', fs: 'NTFS', used: 338 * GB, total: 476 * GB }],
      uptime_s: 3 * 86_400,
      boot_time: iso(3 * 1440),
      top_cpu: [{ name: 'updater.exe', pid: 6120, count: 1, cpu_pct: 71.4, rss: 96 * MB }],
      top_mem: [{ name: 'chrome.exe', count: 31, cpu_pct: 3.5, rss: 3.1 * GB }],
      battery: { percent: 76, charging: false, plugged: false },
    },
  },
};

// 真的 Claude Code／Codex 回答是 Markdown（標題、粗體、表格、清單），桌面版用 ui/markdown.js 顯示
const AI_ANSWER = `## 結論

這台電腦有 **1 組危險連線**、**3 組可疑連線**，其中 **updater.exe 需要立刻處理**。

| 程式 | 目的地 | 判定 | 依據 |
|---|---|---|---|
| updater.exe | 203.0.113.66:443 | 危險（2 條連線） | abuse.ch Feodo Tracker 列名（信心 90%，CC0 1.0），只收錄殭屍網路的控制伺服器；程式從 \`%TEMP%\` 執行並被註冊成服務 UpdaterSvc，誤報機率低 |
| powershell.exe | 198.51.100.80:8443 | 可疑 | CINS Army 列名（75%）＋命令列程式直接連外，先確認是不是 IT 的維運腳本 |
| syncagent.exe | 198.51.100.140:4444 | 可疑 | 沒有情資來源列名，是行為判斷：每 60 秒一次、非常規律，port 4444 也常被遠端控制工具使用 |
| （外部連入） | 198.51.100.23 → 本機 3389 | 可疑 | 遠端桌面被暴力破解（10 分鐘 96 次失敗），blocklist.de 列名 |

## 建議

1. 先隔離這台主機，結束 updater.exe 並停用 UpdaterSvc。
2. 封鎖 203.0.113.66：\`ai-security-monitor fw block 203.0.113.66 --yes\`（或在 Hub 送出封鎖，核准後由 agent 執行）。
3. 用 Microsoft Defender 完整掃描，並**更改這台電腦上登入過的帳號密碼**。
4. 遠端桌面不要直接對外開放，改走 VPN。
`;
const AI_TOOLS = [
  ['list_connections', '{"verdict":["dangerous","suspicious"]}'],
  ['lookup_ip', '{"indicator":"203.0.113.66"}'],
  ['lookup_ip', '{"indicator":"198.51.100.80"}'],
  ['events_summary', '{"days":7}'],
];

const DATA = {
  overview: OVERVIEW,
  connections: { connections: CONNECTIONS, listeners: [], intel_loaded: true },
  latest_report: REPORT,
  intel_feeds: { feeds: INTEL_FEEDS },
  ai_providers: {
    providers: [
      { id: 'claude', label: 'Claude Code', found: true, path: 'C:\\Users\\demo\\AppData\\Roaming\\npm\\claude.cmd', logged_in: true },
      { id: 'codex', label: 'Codex CLI', found: true, path: 'C:\\Users\\demo\\AppData\\Roaming\\npm\\codex.cmd', logged_in: true },
    ],
  },
  ips: {
    '203.0.113.66': { ip: '203.0.113.66', hits: [hit('feodo', '203.0.113.66')], geo: { country: 'NL', asn: 64500, org: 'Example Hosting' }, class: 'Public' },
    '198.51.100.80': { ip: '198.51.100.80', hits: [hit('cins', '198.51.100.80')], geo: { country: 'SG', asn: 64511, org: 'Example VPS' }, class: 'Public' },
    '198.51.100.140': { ip: '198.51.100.140', hits: [], geo: { country: 'DE', asn: 64502, org: 'Example Cloud' }, class: 'Public' },
    '198.51.100.23': { ip: '198.51.100.23', hits: [hit('blocklistde', '198.51.100.23')], geo: { country: 'RU', asn: 64503, org: 'Example Transit' }, class: 'Public' },
  },
  ai: { answer: AI_ANSWER, tools: AI_TOOLS },
  hub_status: { hub_url: 'https://hub.example.com', hub_fingerprint: '72AS-YEXT-VNGO-NLC5-W2NM', pending: null },
  metrics: METRICS,
  update_status: {
    mode: 'notify',
    current: VERSION,
    desktop: { checked_at: iso(95), latest: VERSION, available: false, notes: null, notes_url: null, error: null, ready: false },
    blocker: null,
    auto_install_ok: true,
    releases_url: 'https://github.com/markku636/ai-security-monitor/releases',
    background: { running: 1, uses_desktop: true, cli: [] },
  },
  upload_status: { enrolled: true, last_upload_at: iso(4), last_report_at: iso(4), last_error: null, last_error_at: null, pending: 0 },
  local_hub_status: { found: false, advertise_url: null, lan_ips: ['192.0.2.24'], advertising: null, background_running: true },
  background_service: {
    status: { scope: 'user', manager: 'windows_run', installed: true, legacy: false },
    exe: 'C:\Users\demo\AppData\Local\AI Security Monitor\ai-security-monitor-desktop.exe',
    config_dir: 'C:\Users\demo\AppData\Roaming\ai-security-monitor',
    running: 1,
    legacy_running: false,
  },
};

// 在頁面裡執行：模擬 Tauri 2 的 window.__TAURI__.core.invoke 與 event.listen（withGlobalTauri）
function installMock(D) {
  const listeners = {};
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const emit = (name, payload) => (listeners[name] ?? []).forEach((cb) => cb({ event: name, payload }));
  const handlers = {
    overview: () => D.overview,
    connections: () => D.connections,
    latest_report: () => D.latest_report,
    intel_feeds: () => D.intel_feeds,
    ai_providers: () => D.ai_providers,
    lookup_ip: ({ ip }) => D.ips[ip] ?? { ip, hits: [], geo: null, class: 'Public' },
    scan_now: () => D.latest_report,
    intel_update: () => [],
    open_url: () => null,
    hub_status: () => D.hub_status,
    background_service_status: () => D.background_service,
    desktop_autostart_status: () => true,
    metrics_now: () => D.metrics,
    set_performance: ({ enabled }) => enabled,
    discover_hubs: () => ({ hubs: [], pinned_fingerprint: D.hub_status.hub_fingerprint }),
    update_status: () => D.update_status,
    check_updates: () => ({ ...D.update_status, desktop: { ...D.update_status.desktop, checked_at: new Date().toISOString() } }),
    set_update_mode: ({ mode }) => ((D.update_status.mode = mode), D.update_status),
    upload_status: () => D.upload_status,
    local_hub_status: () => D.local_hub_status,
    ai_ask: async ({ provider }) => {
      emit('ai-event', { type: 'start', provider: provider === 'codex' ? 'Codex CLI' : 'Claude Code' });
      for (const [name, input] of D.ai.tools) {
        emit('ai-event', { type: 'tool', name, input });
        emit('ai-event', { type: 'tool_result', ok: true, preview: '{…}' });
      }
      for (const part of D.ai.answer.match(/[\s\S]{1,80}/g)) emit('ai-event', { type: 'text', text: part });
      await wait(10);
      return { text: D.ai.answer, is_error: false, tools_called: D.ai.tools.length };
    },
  };
  window.__TAURI__ = {
    core: {
      invoke: async (cmd, a = {}) => {
        const h = handlers[cmd];
        if (!h) throw new Error(`mock: unknown command ${cmd}`);
        return structuredClone(await h(a));
      },
    },
    event: {
      listen: async (name, cb) => {
        (listeners[name] ??= []).push(cb);
        return () => (listeners[name] = listeners[name].filter((x) => x !== cb));
      },
    },
  };
}

let FRAME_PAGE = '';

// ---------------- 靜態伺服器（只綁 127.0.0.1） ----------------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png' };
const server = http.createServer((req, res) => {
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
  if (rel === '__frame.html') {
    res.writeHead(200, { 'content-type': MIME['.html'] }).end(FRAME_PAGE);
    return;
  }
  const file = path.resolve(UI, rel);
  if (!file.startsWith(UI + path.sep) || !fs.existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { 'content-type': MIME[path.extname(file)] ?? 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}/index.html`;

// ---------------- 瀏覽器（CDP） ----------------
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
const browser = findBrowser();
if (!browser) {
  console.error('Chrome or Edge not found; pass --browser <path>');
  process.exit(1);
}
fs.mkdirSync(OUT, { recursive: true });

const port = 9300 + Math.floor(Math.random() * 500);
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-security-monitor-desktop-shot-'));
const proc = spawn(browser, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--lang=zh-TW', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
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
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
});
const send = (method, params = {}) =>
  new Promise((r) => {
    const i = ++seq;
    pending.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(`${expression}: ${JSON.stringify(r.result.exceptionDetails)}`);
  return r.result?.result?.value;
};
const waitFor = async (expression, ms = 5000) => {
  for (let t = 0; t < ms; t += 100) {
    if (await evaluate(expression)) return;
    await sleep(100);
  }
  throw new Error(`timeout waiting for ${expression}`);
};

await send('Page.enable');
await send('Runtime.enable');
await send('Page.addScriptToEvaluateOnNewDocument', { source: `(${installMock.toString()})(${JSON.stringify(DATA)});` });

// 名稱｜頁面｜深色｜擷取前要做的事
const SHOTS = [
  ['desktop-overview', 'overview', false, async () => waitFor(`document.querySelector('#ov-conn table') && document.querySelector('#ov-metrics .spark')`)],
  [
    'desktop-connections',
    'connections',
    false,
    async () => {
      await waitFor(`document.querySelector('#tbl table')`);
      await evaluate(`document.querySelector('[data-ip="203.0.113.66"]').click()`);
      await waitFor(`document.getElementById('ip-ai')`);
    },
  ],
  [
    'desktop-findings',
    'findings',
    false,
    async () => {
      await waitFor(`document.querySelector('details')`);
      await evaluate(`document.querySelector('details').open = true`);
    },
  ],
  ['desktop-intel', 'intel', false, async () => waitFor(`document.querySelector('#main table')`)],
  [
    'desktop-ai',
    'ai',
    false,
    async () => {
      await waitFor(`document.getElementById('go')`);
      await evaluate(`document.getElementById('go').click()`);
      await waitFor(`/完成/.test(document.getElementById('status').textContent)`);
    },
  ],
  ['desktop-settings', 'settings', false, async () => waitFor(`document.getElementById('auto-bg') && !document.getElementById('auto-bg').disabled && !document.getElementById('auto-tray').disabled`)],
  [
    'desktop-settings-update',
    'settings',
    false,
    async () => {
      await waitFor(`document.getElementById('upd-check') && !document.getElementById('auto-bg').disabled`);
      await evaluate(`document.getElementById('auto-bg').closest('.card').scrollIntoView()`);
    },
  ],
  ['desktop-overview-dark', 'overview', true, async () => waitFor(`document.querySelector('#ov-conn table') && document.querySelector('#ov-metrics .spark')`)],
];

const only = args.only ? new Set(args.only.split(',')) : null;
const captured = [];
for (const [name, page, dark, prepare] of SHOTS) {
  if (only && !only.has(name)) continue;
  // 桌面版視窗預設 1200×780（tauri.conf.json）；連線頁右邊有 IP 分析欄，用放大後的視窗
  const [width, height] = page === 'connections' ? [1440, 860] : [1200, 780];
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  // 減少動態效果：略過啟動畫面（splash.js），截到的是頁面本身
  await send('Emulation.setEmulatedMedia', {
    features: [
      { name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' },
      { name: 'prefers-reduced-motion', value: 'reduce' },
    ],
  });
  // 和真的 app 一樣先開總覽（側欄的主機名稱、版本、背景服務狀態是總覽載入時填的），再切到要拍的頁
  await send('Page.navigate', { url: `${BASE}?${name}#overview` });
  await waitFor(`document.readyState === 'complete' && document.getElementById('brand-host').textContent === 'fin-laptop-07' && !!document.querySelector('#ov-conn table')`);
  if (page !== 'overview') {
    await evaluate(`location.hash = '#${page}'`);
    await waitFor(`document.querySelector('#nav a.active')?.dataset.page === '${page}' && !/載入中/.test(document.querySelector('#main .sub')?.textContent ?? '')`);
  }
  // 先回到頁首（prepare 裡要拍下面某一段的自己捲過去）
  await evaluate(`document.getElementById('main').scrollTop = 0`);
  await prepare();
  await sleep(400);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  if (FRAME) {
    captured.push({ name, dark, width, height, img: `data:image/png;base64,${shot.result.data}` });
    continue;
  }
  fs.writeFileSync(path.join(OUT, `${name}.png`), Buffer.from(shot.result.data, 'base64'));
  console.log(`${name}.png`);
}

// --frame windows：把剛拍好的畫面放進自己畫的視窗外框，再拍一次
async function renderFrame(file, { W, H, html }) {
  FRAME_PAGE = html;
  await send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: BASE.replace('index.html', `__frame.html?${file}`) });
  await waitFor(`document.readyState === 'complete' && [...document.images].every((i) => i.complete && i.naturalWidth > 0)`);
  await sleep(200);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, file), Buffer.from(shot.result.data, 'base64'));
  console.log(file);
}
for (const c of captured) await renderFrame(`windows-${c.name}.png`, framedPage(c.img, c.width, c.height, c.dark));
for (const c of captured.filter((x) => x.name === 'desktop-overview' || x.name === 'desktop-overview-dark')) {
  await renderFrame(c.dark ? 'windows-desktop-hero-dark.png' : 'windows-desktop-hero.png', heroPage(c.img, c.width, c.height, c.dark));
}
ws.close();
proc.kill();
server.close();
