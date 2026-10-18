// README 截圖（桌面版）：在本機用靜態伺服器提供 desktop/ui，注入假的 window.__TAURI__（示範資料），
// 再用無頭 Chrome／Edge（CDP）擷取各頁。完全不碰真實設定目錄、不跑真的掃描、不呼叫 AI。
//   node scripts/capture-desktop-screenshots.mjs [--out docs/images] [--browser <path>] [--only desktop-overview,…]
//   檢查別的視窗大小：--size 1200x810 [--dark]（全部頁面用這個大小、深色；搭配 --out 存到別處，別蓋掉 README 的圖）
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
const SIZE = args.size?.match(/^(\d+)x(\d+)$/)?.slice(1).map(Number) ?? null;
const FORCE_DARK = 'dark' in args;
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
      commercial_ok: x.license?.commercial_ok !== false,
      license_blocked: false,
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

// 「效能與流量」頁（metrics_history）：最近 1 小時每分鐘一點、最近 24 小時每 5 分鐘一點。
// 故事和總覽一致：辦公時段的起伏，最後幾分鐘 updater.exe 一直往外傳；24 小時裡半夜筆電睡著（沒有資料，圖上斷開）。
const DISKS = [
  { mount: 'C:\\', fs: 'NTFS', used: 338 * GB, total: 476 * GB },
  { mount: 'D:\\', fs: 'NTFS', used: 731 * GB, total: 931 * GB },
];
METRICS.current.perf.disks = DISKS;
METRICS.current.perf.disk_read_bytes = 38 * MB * 60;
METRICS.current.perf.disk_write_bytes = 12 * MB * 60;
METRICS.current.perf.top_cpu = [
  { name: 'updater.exe', pid: 6120, count: 1, cpu_pct: 71.4, rss: 96 * MB },
  { name: 'chrome.exe', count: 31, cpu_pct: 6.2, rss: 3.1 * GB },
  { name: 'MsMpEng.exe', pid: 3312, count: 1, cpu_pct: 4.8, rss: 310 * MB },
  { name: 'Teams.exe', count: 6, cpu_pct: 2.9, rss: 1.2 * GB },
  { name: 'Code.exe', count: 9, cpu_pct: 1.7, rss: 1.4 * GB },
];
METRICS.current.perf.top_mem = [
  { name: 'chrome.exe', count: 31, cpu_pct: 6.2, rss: 3.1 * GB },
  { name: 'Code.exe', count: 9, cpu_pct: 1.7, rss: 1.4 * GB },
  { name: 'Teams.exe', count: 6, cpu_pct: 2.9, rss: 1.2 * GB },
  { name: 'OneDrive.exe', pid: 8840, count: 1, cpu_pct: 0.4, rss: 420 * MB },
  { name: 'MsMpEng.exe', pid: 3312, count: 1, cpu_pct: 4.8, rss: 310 * MB },
];
METRICS.current.net.processes = [
  { name: 'updater.exe', rx_bytes: 0.02 * MB * 60, tx_bytes: 5.8 * MB * 60 },
  { name: 'chrome.exe', rx_bytes: 0.6 * MB * 60, tx_bytes: 0.05 * MB * 60 },
];
METRICS.current.net.process_source = 'estats';

/** 一個時間點的各程式速率（B/s）：活躍度 a（0–1）、i 讓曲線有起伏、upload＝updater.exe 往外傳。 */
function demoProcs(a, i, upload) {
  const w = (k) => 0.75 + 0.25 * Math.sin(i / 3.1 + k);
  const procs = [
    { name: 'chrome.exe', rx: 620 * 1024 * a * w(1), tx: 48 * 1024 * a * w(2) },
    { name: 'Teams.exe', rx: 190 * 1024 * a * w(3), tx: 140 * 1024 * a * w(4) },
    { name: 'OneDrive.exe', rx: (i % 17 < 3 ? 900 : 40) * 1024 * a, tx: (i % 23 < 2 ? 700 : 20) * 1024 * a },
    { name: 'updater.exe', rx: upload ? 18 * 1024 : 0, tx: upload ? 5.8 * MB : 0 },
    { name: 'svchost.exe', rx: 36 * 1024 * (0.4 + a) * w(5), tx: 9 * 1024 * (0.4 + a) },
    { name: 'msedge.exe', rx: 70 * 1024 * a * w(6), tx: 8 * 1024 * a },
    { name: 'Code.exe', rx: 22 * 1024 * a * w(7), tx: 6 * 1024 * a },
  ].filter((p) => p.rx + p.tx > 0);
  return { procs, procs_other: { name: '', rx: 30 * 1024 * a, tx: 6 * 1024 * a } };
}

function demoPoint(ts, secs, a, i, upload) {
  const { procs, procs_other } = demoProcs(a, i, upload);
  const rx = procs.reduce((s, p) => s + p.rx, 0) * 1.08 + procs_other.rx;
  const tx = procs.reduce((s, p) => s + p.tx, 0) * 1.08 + procs_other.tx;
  const cpu = upload ? 88 + 4 * Math.sin(i) : 6 + 22 * a + 6 * Math.sin(i / 2.7);
  return {
    ts,
    secs,
    rx,
    tx,
    procs,
    procs_other,
    cpu: Math.round(cpu * 10) / 10,
    cpu_max: Math.round(Math.min(100, cpu * (1.6 + 0.3 * Math.sin(i))) * 10) / 10,
    mem_used: Math.round(16 * GB * (0.52 + 0.18 * a + 0.03 * Math.sin(i / 5))),
    mem_total: 16 * GB,
    disk_read: (2 + 30 * a * (0.6 + 0.4 * Math.sin(i / 1.9))) * MB * (i % 29 === 0 ? 3 : 1),
    disk_write: (0.8 + 9 * a * (0.6 + 0.4 * Math.cos(i / 2.3))) * MB,
  };
}

// 圖上的時間固定在當地今天 17:32（不管什麼時候跑這個腳本，24 小時圖的上班／半夜起伏都在對的鐘點）
const USAGE_NOW = new Date(new Date(now).setHours(17, 32, 0, 0)).getTime();
const HOUR_POINTS = Array.from({ length: 60 }, (_, k) => {
  const i = 59 - k;
  const ts = new Date(Math.floor((USAGE_NOW - i * 60_000) / 60_000) * 60_000).toISOString();
  return { ...demoPoint(ts, 60, 0.7 + 0.25 * Math.sin(k / 6), k, i < 6), battery: Math.round(76 + i * 0.25) };
});
const DAY_POINTS = Array.from({ length: 288 }, (_, k) => {
  const i = 287 - k;
  const t = Math.floor((USAGE_NOW - i * 300_000) / 300_000) * 300_000;
  const ts = new Date(t).toISOString();
  const h = new Date(t).getHours() + new Date(t).getMinutes() / 60;
  // 01:00–06:30 筆電睡著：沒有資料
  if (h >= 1 && h < 6.5) return { ts, secs: 0 };
  const a = h >= 9 && h < 18.5 ? 0.75 + 0.2 * Math.sin(k / 9) : h >= 18.5 && h < 23 ? 0.35 : 0.12;
  const battery = Math.max(18, Math.min(100, Math.round(h >= 9 && h < 13 ? 100 - (h - 9) * 9 : h >= 13 && h < 14 ? 64 + (h - 13) * 30 : h >= 14 && h < 18.5 ? 94 - (h - 14) * 4 : 90)));
  return { ...demoPoint(ts, 300, a, k, i < 2), battery };
});
const usageHistory = (range) => ({
  range,
  step_s: range === '24h' ? 300 : 60,
  source: 'background',
  interval: '1m',
  performance_enabled: true,
  process_network: true,
  has_processes: true,
  platform: 'windows',
  elevated: false,
  points: range === '24h' ? DAY_POINTS : HOUR_POINTS,
  current: METRICS.current,
});

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
  // 線上查詢金鑰：AbuseIPDB 用付費方案、GreyNoise 有免費金鑰、CrowdSec 沒設
  intel_keys: {
    online_lookups: true,
    noncommercial: true,
    providers: [
      { id: 'abuseipdb', name: 'AbuseIPDB check', vendor: 'AbuseIPDB', license: 'AbuseIPDB ToS (free tier 1000/day, non-commercial)', commercial_ok: false, has_key: true, paid: true, paid_supported: true, usable: true },
      { id: 'greynoise-community', name: 'GreyNoise Community', vendor: 'GreyNoise', license: 'GreyNoise Community ToS', commercial_ok: false, has_key: true, paid: false, paid_supported: false, usable: true },
      { id: 'crowdsec-cti', name: 'CrowdSec CTI smoke', vendor: 'CrowdSec', license: 'CrowdSec CTI ToS (community key)', commercial_ok: false, has_key: false, paid: false, paid_supported: true, usable: false },
    ],
  },
  // 示範機是個人用：只限非商業用途的來源也開著（情資頁會標「非商用」）
  intel_usage: {
    usage: 'noncommercial',
    noncommercial: true,
    sources: registry.feeds
      .filter((x) => x.license?.commercial_ok === false)
      .map((x) => ({ id: x.id, name: x.name, vendor: x.vendor, license: x.license.name, lookup: x.format === 'lookup-api' })),
  },
  dns: (() => {
    const t = (m) => new Date(Date.now() - m * 60_000).toISOString();
    const rec = (m, name, process, rcode = 'NOERROR', count = 1, answers = [], reasons = [], qtype = 'A') => ({ ts: t(m), name, qtype, rcode, process, count, answers, reasons });
    const records = [
      rec(1, 'teams.microsoft.com', 'ms-teams.exe', 'NOERROR', 4, ['52.113.194.132']),
      rec(2, 'kqfcpqbyqllgbr.net', 'rundll32.exe', 'NXDOMAIN', 2, [], ['看起來像亂數產生的網域']),
      rec(2, 'pbqwnzlkhtrdve.net', 'rundll32.exe', 'NXDOMAIN', 2, [], ['看起來像亂數產生的網域']),
      rec(3, 'outlook.office365.com', 'OUTLOOK.EXE', 'NOERROR', 3, ['52.98.152.178']),
      rec(4, 'cdn-update.example-malware.test', 'updater.exe', 'NOERROR', 5, ['203.0.113.66'], ['情資：CERT Polska 警示清單（分數 85）']),
      rec(5, 'www.google.com', 'chrome.exe', 'NOERROR', 6, ['142.250.196.196']),
      rec(6, 'dns.google', 'helper.exe', 'NOERROR', 1, ['8.8.8.8'], ['加密 DNS 端點（HaGeZi DoH）']),
      rec(7, 'login.microsoftonline.com', 'chrome.exe', 'NOERROR', 2, ['20.190.160.20']),
      rec(9, 'github.com', 'Code.exe', 'NOERROR', 2, ['140.82.112.3']),
      rec(12, 'ctldl.windowsupdate.com', 'svchost.exe', 'NOERROR', 1, ['93.184.221.240']),
    ];
    return {
      records,
      total: 1842,
      nxdomain: 38,
      suspicious: 4,
      domains: 126,
      top_domains: [
        { domain: 'microsoft.com', count: 412, process: 'ms-teams.exe' },
        { domain: 'office365.com', count: 233, process: 'OUTLOOK.EXE' },
        { domain: 'google.com', count: 198, process: 'chrome.exe' },
        { domain: 'github.com', count: 96, process: 'Code.exe' },
        { domain: 'windowsupdate.com', count: 41, process: 'svchost.exe' },
      ],
      top_processes: [
        { process: 'chrome.exe', count: 702 },
        { process: 'ms-teams.exe', count: 455 },
        { process: 'OUTLOOK.EXE', count: 233 },
        { process: 'Code.exe', count: 120 },
        { process: 'rundll32.exe', count: 24 },
      ],
      status: { source: 'etw', running: true, events: 18_420, deduped: 2_100, dropped: 0, last_event_at: t(0), has_process: true },
      unreadable: false,
      enabled: true,
      upload: 'all',
      use_hub: null,
      hub_protect: { enabled: true, resolver_ips: ['192.0.2.53'], block: ['login.microsoft-verify.test'] },
      dns_server: false,
      dns_server_listen: '',
      verify_answers: false,
      blocklist: {
        local: [{ domain: 'cdn-update.example-malware.test', added_at: t(30), note: '釣魚信裡的連結' }],
        hub: ['login.microsoft-verify.test'],
      },
      allowlist: { local: ['intranet.corp.example'], hub: ['ok.example.com'] },
    };
  })(),
  // 網域分析（DNS 頁點網域或輸入網域按查詢）
  domains: {
    'cdn-update.example-malware.test': {
      domain: 'cdn-update.example-malware.test',
      registrable: 'example-malware.test',
      popular: false,
      resolved: { ok: true, addrs: ['203.0.113.66'] },
      use_hub: false,
      block: { entry: 'cdn-update.example-malware.test', source: '這台電腦的黑名單', local: true },
      allowed: false,
      allowed_local: null,
      intel: {
        loaded: true,
        score: 85,
        hits: [{ feed_id: 'certpl-domains', name: '警示清單', vendor: 'CERT Polska', confidence: 85, license: 'CERT.PL terms', source_url: 'https://cert.pl/en/warning-list/', matched: 'cdn-update.example-malware.test' }],
      },
      doh: null,
      heuristic: null,
      recent: {
        total: 37,
        last: new Date(Date.now() - 4 * 60_000).toISOString(),
        processes: [{ process: 'updater.exe', count: 35 }, { process: 'chrome.exe', count: 2 }],
        rcodes: [{ rcode: 'NOERROR', count: 37 }],
        names: [{ name: 'cdn-update.example-malware.test', count: 37 }],
        answers: ['203.0.113.66'],
      },
    },
  },
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
  // 「設定 → 公司的 Security Hub」還沒加入時找到的 Hub：同一個 Hub 從公司 DNS 和區網廣播各找到一次，另一個連不到
  discovered: [
    {
      url: 'https://hub.example.com',
      source: 'dns_srv',
      detail: 'example.com',
      identity: { name: 'Example Corp Security Hub', version: VERSION, edition: 'server', fingerprint: '72AS-YEXT-VNGO-NLC5-W2NM', enrollment: { keyless: true, mode: 'auto' } },
    },
    {
      url: 'http://192.0.2.10:8088',
      source: 'mdns',
      detail: 'Example Corp Security Hub._aisecmon._tcp.local.',
      identity: { name: 'Example Corp Security Hub', version: VERSION, edition: 'server', fingerprint: '72AS-YEXT-VNGO-NLC5-W2NM', enrollment: { keyless: true, mode: 'auto' } },
    },
    { url: 'http://198.51.100.40:8088', source: 'mdns', detail: 'lab-hub._aisecmon._tcp.local.', error: '連不到（5 秒逾時）' },
  ],
  metrics: METRICS,
  usage: { '1h': usageHistory('1h'), '24h': usageHistory('24h') },
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
  // 網址的 ?<截圖名稱>：-join 結尾的截圖用「還沒加入 Hub」的狀態
  if (location.search.endsWith('-join')) {
    D.hub_status = { hub_url: null, hub_fingerprint: null, pending: null };
    D.overview.hub_url = null;
    D.upload_status.enrolled = false;
  }
  // -first-run 結尾的截圖：還沒選過情資的使用情境（第一次打開會跳出選擇視窗）
  if (location.search.endsWith('-first-run')) D.intel_usage = { ...D.intel_usage, usage: null, noncommercial: false };
  const emit = (name, payload) => (listeners[name] ?? []).forEach((cb) => cb({ event: name, payload }));
  const handlers = {
    overview: () => D.overview,
    connections: () => D.connections,
    latest_report: () => D.latest_report,
    intel_feeds: () => D.intel_feeds,
    intel_usage: () => D.intel_usage,
    intel_keys: () => D.intel_keys,
    set_intel_key: () => ({ ok: true }),
    set_online_lookups: ({ enabled }) => enabled,
    set_intel_usage: ({ usage }) => {
      D.intel_usage = { ...D.intel_usage, usage, noncommercial: usage === 'noncommercial' };
      return { usage };
    },
    dns_recent: () => D.dns,
    dns_settings: () => D.dns,
    lookup_domain: ({ domain }) =>
      D.domains[domain] ?? { domain, registrable: domain, popular: false, resolved: { ok: true, addrs: [] }, use_hub: false, block: null, allowed: false, allowed_local: null, intel: { loaded: true, score: 0, hits: [] }, doh: null, heuristic: null, recent: { total: 0, last: null, processes: [], rcodes: [], names: [], answers: [] } },
    ai_providers: () => D.ai_providers,
    ai_auth_status: () => ({
      providers: [
        { id: 'claude', label: 'Claude Code', installed: true, logged_in: true, method: 'claude.ai', email: 'demo@example.com', plan: 'pro', env_override: [] },
        { id: 'codex', label: 'Codex CLI', installed: true, logged_in: true, method: 'chatgpt', env_override: [] },
      ],
    }),
    lookup_ip: ({ ip }) => D.ips[ip] ?? { ip, hits: [], geo: null, class: 'Public' },
    scan_now: () => D.latest_report,
    intel_update: () => [],
    open_url: () => null,
    hub_status: () => D.hub_status,
    background_service_status: () => D.background_service,
    desktop_autostart_status: () => true,
    metrics_now: () => D.metrics,
    metrics_history: ({ range }) => D.usage[range] ?? D.usage['1h'],
    // 即時流量：每次呼叫回一個平滑變化的假樣本
    traffic_live: () => {
      const k = (window.__liveK = (window.__liveK ?? 0) + 1);
      const rx = Math.round(2.4e6 + 1.6e6 * Math.sin(k / 4) + 0.5e6 * Math.sin(k / 1.7));
      const tx = Math.round(3.2e5 + 2.4e5 * Math.sin(k / 3 + 1));
      return {
        ready: true, elapsed_s: 1, rx_rate: rx, tx_rate: tx, rx_bytes: rx, tx_bytes: tx, elevated: true, os: 'windows', process_source: 'estats',
        interfaces: [
          { name: 'Wi-Fi', virtual: false, rx_rate: rx, tx_rate: tx },
          { name: 'vEthernet (WSL)', virtual: true, rx_rate: Math.round(rx * 0.08), tx_rate: Math.round(tx * 0.05) },
        ],
        processes: [
          { name: 'msedge.exe', rx_rate: Math.round(rx * 0.55), tx_rate: Math.round(tx * 0.3) },
          { name: 'OneDrive.exe', rx_rate: Math.round(rx * 0.05), tx_rate: Math.round(tx * 0.55) },
          { name: 'Teams.exe', rx_rate: Math.round(rx * 0.25), tx_rate: Math.round(tx * 0.12) },
          { name: 'svchost.exe', rx_rate: Math.round(rx * 0.1), tx_rate: Math.round(tx * 0.03) },
        ],
      };
    },
    set_performance: ({ enabled }) => enabled,
    discover_hubs: async () => {
      await wait(300);
      return { hubs: D.hub_status.hub_url ? [] : D.discovered, pinned_fingerprint: D.hub_status.hub_fingerprint };
    },
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
  [
    'desktop-traffic',
    'traffic',
    false,
    async () => {
      await waitFor(`document.querySelector('.live-rx')`, 10000);
      // 不用真的等 60 秒：直接補滿 60 個樣本再畫一次
      await evaluate(
        `for (let i = 0; i < 60; i++) { const k = i + 1; liveState.points.push({ rx: 2.4e6 + 1.6e6 * Math.sin(k / 4) + 0.5e6 * Math.sin(k / 1.7), tx: 3.2e5 + 2.4e5 * Math.sin(k / 3 + 1) }); } liveState.points = liveState.points.slice(-60); renderLive(); true`,
      );
    },
  ],
  // DNS：點一個被情資列名的網域，右邊滑出網域分析
  [
    'desktop-dns',
    'dns',
    false,
    async () => {
      await waitFor(`document.querySelector('#main table')`);
      await evaluate(`document.querySelector('[data-domain="cdn-update.example-malware.test"]').click()`);
      await waitFor(`document.getElementById('dom-ai')`);
    },
  ],
  // 第一次打開：問這台電腦是公司用還是個人用
  ['desktop-first-run', 'overview', false, async () => waitFor(`document.querySelector('.overlay .choice') && document.querySelector('#ov-conn table')`)],
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
  // 設定頁的 DNS 區塊：監看開關、上傳、防護 DNS、黑白名單
  [
    'desktop-settings-dns',
    'settings/dns',
    false,
    async () => {
      await waitFor(`document.getElementById('dns-set-enabled') && !document.getElementById('auto-bg').disabled`);
      await evaluate(`document.getElementById('set-dns').scrollIntoView(); true`);
      await sleep(1700);
    },
  ],
  // 還沒加入 Hub：設定頁的 Hub 區塊自動尋找，列出找到的 Hub
  ['desktop-settings-join', 'settings', false, async () => waitFor(`document.querySelector('#join-found table') && !document.getElementById('join-search').disabled`)],
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
  // 流量與效能 → 最近 1 小時：滑鼠停在網路速度圖上（十字線＋各線的值）
  [
    'desktop-usage',
    'traffic/1h',
    false,
    async () => {
      await waitFor(`document.querySelector('#us-net .tchart-svg path') && document.querySelector('#us-procs .tchart-svg path') && document.querySelector('#us-cpu .tchart-svg path')`);
      await evaluate(`(() => {
        const s = document.querySelector('#us-net .tchart-svg');
        const r = s.getBoundingClientRect();
        s.dispatchEvent(new PointerEvent('pointermove', { clientX: r.left + r.width * 0.78, clientY: r.top + r.height / 2, bubbles: true }));
      })()`);
      await waitFor(`!document.querySelector('#us-net .tchart-tip').hidden`);
    },
  ],
  // 同一頁往下：CPU、記憶體、磁碟讀寫、各磁碟區、最吃資源的程式、電池
  [
    'desktop-usage-perf',
    'traffic/1h',
    false,
    async () => {
      await waitFor(`document.querySelector('#us-cpu .tchart-svg path') && document.querySelector('#us-top table') && document.querySelector('#us-battery .tchart-svg path')`);
      await evaluate(`document.getElementById('us-cpu').closest('.card').scrollIntoView({ block: 'start' })`);
    },
  ],
  // 深色＋最近 24 小時（半夜筆電睡著的時段沒有資料，圖上斷開）
  [
    'desktop-usage-dark',
    'traffic/24h',
    true,
    async () => waitFor(`/5 分鐘/.test(document.getElementById('us-source').textContent) && document.querySelector('#us-cpu .tchart-svg path')`),
  ],
];

const only = args.only ? new Set(args.only.split(',')) : null;
const captured = [];
for (const [name, page, dark, prepare] of SHOTS) {
  if (only && !only.has(name)) continue;
  // 桌面版視窗預設 1200×780（tauri.conf.json）；連線頁右邊會滑出 IP 分析面板，用放大後的視窗
  // 流量與效能的歷史分頁比較長：用加高的視窗
  const [width, height] = SIZE ?? (page === 'connections' ? [1440, 860] : page.startsWith('traffic/') ? [1200, 960] : [1200, 780]);
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  // 減少動態效果：略過啟動畫面（splash.js），截到的是頁面本身
  await send('Emulation.setEmulatedMedia', {
    features: [
      { name: 'prefers-color-scheme', value: dark || FORCE_DARK ? 'dark' : 'light' },
      { name: 'prefers-reduced-motion', value: 'reduce' },
    ],
  });
  // 和真的 app 一樣先開總覽（側欄的主機名稱、版本、背景服務狀態是總覽載入時填的），再切到要拍的頁
  await send('Page.navigate', { url: `${BASE}?${name}#overview` });
  await waitFor(`document.readyState === 'complete' && document.getElementById('brand-host').textContent === 'fin-laptop-07' && !!document.querySelector('#ov-conn table')`);
  if (page !== 'overview') {
    await evaluate(`location.hash = '#${page}'`);
    // page 可以帶區塊（traffic/1h）：側欄比對的是 / 前面的頁名
    await waitFor(`document.querySelector('#nav a.active')?.dataset.page === '${page.split('/')[0]}' && !/載入中/.test(document.querySelector('#main .sub')?.textContent ?? '')`);
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
