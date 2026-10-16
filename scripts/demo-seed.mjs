// 示範資料：四台虛構主機（文件保留網段 IP），經由正式的 ingest API 送進 Security Hub，供截圖與試玩。
//   node scripts/demo-seed.mjs --hub http://127.0.0.1:3000 --admin <ASA_HUB_ADMIN_SECRET>
// Hub 要能收到過去時間的報告：會用網頁 API 建一把註冊金鑰，每台送 6 份報告（每小時一份）＋連線快照。
import crypto from 'node:crypto';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const HUB = (args.hub ?? process.env.ASA_HUB_URL ?? 'http://127.0.0.1:3000').replace(/\/$/, '');
const ADMIN = args.admin ?? process.env.ASA_HUB_ADMIN_SECRET;
if (!ADMIN) {
  console.error('usage: node scripts/demo-seed.mjs --hub <url> --admin <admin secret>');
  process.exit(2);
}

const now = Date.now();
const iso = (minsAgo) => new Date(now - minsAgo * 60_000).toISOString();
const hex = (s, n = 16) => crypto.createHash('sha256').update(s).digest('hex').slice(0, n);
const uuid = (s) => {
  const h = hex(s, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

const FEEDS = {
  feodo: {
    feed_id: 'abusech-feodo',
    name: 'Feodo Tracker (recommended)',
    vendor: 'abuse.ch',
    confidence: 90,
    license: 'CC0 1.0',
    license_url: 'https://creativecommons.org/publicdomain/zero/1.0/',
    attribution_required: false,
    source_url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
  },
  blocklistde: {
    feed_id: 'blocklist-de-all',
    name: 'blocklist.de all attacks',
    vendor: 'blocklist.de',
    confidence: 80,
    license: 'Free use with attribution',
    license_url: 'https://www.blocklist.de/en/index.html',
    attribution_required: true,
    source_url: 'https://lists.blocklist.de/lists/all.txt',
  },
  cins: {
    feed_id: 'cins-army',
    name: 'CINS Army list',
    vendor: 'CINS',
    confidence: 75,
    license: 'Free use with attribution',
    license_url: 'https://cinsscore.com/',
    attribution_required: true,
    source_url: 'https://cinsscore.com/list/ci-badguys.txt',
  },
};
const hit = (feed, ip) => ({ ...FEEDS[feed], fetched_at: iso(90), matched: ip, extra: { commercial_ok: true } });

function finding(host, f) {
  return {
    id: `f_${hex(`${host}|${f.scanner}|${f.rule}|${f.key ?? f.title}`)}`,
    scanner: f.scanner,
    rule: f.rule,
    severity: f.severity,
    title: f.title,
    detail: f.detail ?? '',
    evidence: f.evidence ?? { type: 'text', detail: f.title },
    intel_hits: f.intel_hits ?? [],
    recommendation: f.recommendation ?? '',
    actions: f.actions ?? [],
    first_seen: iso(f.since ?? 600),
    last_seen: iso(5),
    tags: f.tags ?? [],
    refs: f.refs ?? [],
  };
}

function conn(c) {
  return {
    proto: c.proto ?? 'tcp',
    local_ip: c.local_ip,
    local_port: c.local_port ?? 50000 + Math.floor(Math.random() * 10000),
    remote_ip: c.remote_ip,
    remote_port: c.remote_port,
    state: c.state ?? 'ESTABLISHED',
    direction: c.direction ?? 'outbound',
    process: c.process,
    geo: c.geo,
    verdict: c.verdict ?? { level: 'unknown', reasons: [] },
  };
}

const hardeningResult = (id, title, severity, result, observed, expected, remediation, category = 'hardening') => ({
  id,
  category,
  severity,
  title,
  result,
  observed,
  expected,
  remediation,
  rationale: '',
  references: ['https://learn.microsoft.com/windows/security/'],
});

// ---------------- 主機 ----------------
const HOSTS = [
  {
    hostname: 'web-01',
    os: { family: 'linux', name: 'Ubuntu 24.04.1 LTS', version: '24.04', kernel: '6.8.0-45-generic' },
    ip: '192.0.2.21',
    elevated: true,
    score: { overall: 71, connections: 78, exposure: 60, vulns: 70, hardening: 74 },
    findings: [
      {
        scanner: 'intel',
        rule: 'intel.inbound_match',
        severity: 'high',
        title: '來自威脅情資列名 IP 的 SSH 連線：198.51.100.23',
        detail: 'sshd ← 198.51.100.23:51522（判定：可疑）。來源：blocklist.de（80%）',
        key: '198.51.100.23',
        evidence: { type: 'connection', remote_ip: '198.51.100.23', remote_port: 51522, local_port: 22, direction: 'inbound' },
        intel_hits: [hit('blocklistde', '198.51.100.23')],
        recommendation: 'asa fw block 198.51.100.23 --yes',
        actions: [{ kind: 'block_ip', params: { ip: '198.51.100.23', direction: 'inbound' }, requires_elevation: true, destructive: false, reversible: true, description: 'Block 198.51.100.23 inbound' }],
        tags: ['inbound'],
      },
      {
        scanner: 'hardening',
        rule: 'hardening.lin.ssh.password_auth',
        severity: 'medium',
        title: '未通過：SSH 只用金鑰登入（關閉密碼登入）',
        detail: '對外開放的 SSH 每天都會收到成千上萬次密碼猜測。',
        key: 'lin.ssh.password_auth',
        evidence: { type: 'policy', policy_id: 'lin.ssh.password_auth', check: 'SSH password login', observed: 'yes', expected: '= no', result: 'fail' },
        recommendation: '確認金鑰可登入後，設定 PasswordAuthentication no 並 reload sshd。',
        tags: ['remote'],
      },
      {
        scanner: 'vuln',
        rule: 'vuln.osv_package',
        severity: 'critical',
        title: 'openssh 1:9.6p1-3ubuntu13 有 2 個已公告漏洞',
        detail: 'CVE-2024-6387 (regreSSHion)',
        key: 'openssh',
        evidence: { type: 'package', ecosystem: 'Ubuntu:24.04:LTS', name: 'openssh', version: '1:9.6p1-3ubuntu13' },
        recommendation: 'sudo apt update && sudo apt upgrade',
        refs: ['https://osv.dev/list?ecosystem=Ubuntu:24.04:LTS&q=openssh'],
        tags: ['kev'],
      },
    ],
    vuln: {
      os: { family: 'linux', name: 'Ubuntu 24.04.1 LTS', version: '24.04' },
      support: { product: 'Ubuntu 24.04.1 LTS', eol: '2029-05-31', status: 'supported', days_left: 955 },
      pending_updates: { total: 23, security: 7 },
      packages: 812,
      by_ecosystem: { dpkg: 812 },
      app_hits: [],
      osv: {
        ecosystem: 'Ubuntu:24.04:LTS',
        queried: 812,
        packages: [
          { name: 'openssh', version: '1:9.6p1-3ubuntu13', ids: ['UBUNTU-CVE-2024-6387', 'UBUNTU-CVE-2024-6409'], cves: ['CVE-2024-6387', 'CVE-2024-6409'], kev: [], severity: 'critical', summary: 'regreSSHion: signal handler race in sshd' },
          { name: 'glibc', version: '2.39-0ubuntu8', ids: ['UBUNTU-CVE-2024-2961'], cves: ['CVE-2024-2961'], kev: [], severity: 'high', summary: 'iconv buffer overflow' },
        ],
      },
      kev_count: 0,
      notes: [],
    },
    hardening: {
      os_family: 'linux',
      pass: 19,
      fail: 3,
      na: 2,
      error: 0,
      score: 74,
      needs_admin: [],
      results: [
        hardeningResult('lin.ssh.password_auth', 'SSH 只用金鑰登入（關閉密碼登入）', 'medium', 'fail', 'yes', '= no', '設定 PasswordAuthentication no 並 reload sshd。', 'remote'),
        hardeningResult('lin.ssh.brute_force_guard', '有 fail2ban／CrowdSec／sshguard 擋暴力破解', 'low', 'fail', 'inactive', '= active', 'apt install fail2ban', 'remote'),
        hardeningResult('lin.audit.auditd', 'auditd 稽核服務在執行', 'low', 'fail', 'inactive', '= active', 'apt install auditd', 'logging'),
        hardeningResult('lin.kernel.aslr', '記憶體位址隨機化（ASLR）完整開啟', 'high', 'pass', '2', '= 2', '', 'kernel'),
        hardeningResult('lin.mac.enforcing', 'AppArmor 或 SELinux 已啟用', 'medium', 'pass', 'apparmor', 'in apparmor, selinux', '', 'hardening'),
      ],
    },
    events: {
      platform: 'linux',
      days: 7,
      events_read: 4210,
      counts_by_level: { error: 14, warning: 120 },
      crash_counts: { oom: 1 },
      crashes: [{ kind: 'oom', time: iso(300), name: 'node', process: 'node', likely_causes: ['Memory limit too low for the workload'], remediation: 'Raise the memory limit or add swap', source: 'journal' }],
      security: [
        { rule: 'failed_logon_burst', severity: 'high', count: 412, first: iso(240), last: iso(8), source_ip: '198.51.100.23', detail: 'max 96 in 10 min', intel: [{ feed_id: 'blocklist-de-all', vendor: 'blocklist.de', confidence: 80, source_url: FEEDS.blocklistde.source_url }], samples: [] },
      ],
      top_error_sources: [],
      needs_admin: [],
      notes: [],
    },
    connections: [
      { local_ip: '192.0.2.21', local_port: 22, remote_ip: '198.51.100.23', remote_port: 51522, direction: 'inbound', process: { pid: 812, name: 'sshd' }, geo: { country: 'RU', asn: 64511, org: 'Example Transit' }, verdict: { level: 'suspicious', reasons: [{ type: 'intel_hit', ...hit('blocklistde', '198.51.100.23') }] } },
      { local_ip: '192.0.2.21', remote_ip: '203.0.113.10', remote_port: 443, process: { pid: 1201, name: 'node' }, geo: { country: 'US', org: 'Example CDN' }, verdict: { level: 'safe', reasons: [{ type: 'known_good', list: 'cdn' }] } },
      { local_ip: '192.0.2.21', remote_ip: '192.0.2.40', remote_port: 5432, process: { pid: 1201, name: 'node' }, verdict: { level: 'safe', reasons: [{ type: 'private_network' }] } },
    ],
    listeners: [{ proto: 'tcp', bind_ip: '0.0.0.0', port: 22, process: { pid: 812, name: 'sshd' }, exposed: true, reachability: { state: 'open' } }],
  },
  {
    hostname: 'db-02',
    os: { family: 'linux', name: 'Rocky Linux 9.4 (Blue Onyx)', version: '9.4', kernel: '5.14.0-427' },
    ip: '192.0.2.40',
    elevated: true,
    score: { overall: 79, connections: 95, exposure: 64, vulns: 82, hardening: 80 },
    findings: [
      {
        scanner: 'ports',
        rule: 'ports.exposed_open',
        severity: 'high',
        title: 'PostgreSQL（tcp 5432）可從網路連入',
        detail: 'postgres 綁在 0.0.0.0:5432，防火牆允許連入。',
        key: 'tcp/5432',
        evidence: { type: 'port', proto: 'tcp', port: 5432, bind: '0.0.0.0', process: 'postgres', reachability: 'open' },
        recommendation: '只允許應用伺服器的位址連入（asa fw close-port tcp/5432 或改 listen_addresses）。',
        tags: ['exposure'],
      },
      {
        scanner: 'vuln',
        rule: 'vuln.pending_security_updates',
        severity: 'medium',
        title: '有 4 個安全性更新還沒安裝（共 31 個待更新）',
        key: 'pending',
        recommendation: 'sudo dnf upgrade --security',
      },
    ],
    vuln: {
      os: { family: 'linux', name: 'Rocky Linux 9.4 (Blue Onyx)', version: '9.4' },
      support: { product: 'Rocky Linux 9.4 (Blue Onyx)', eol: '2032-05-31', status: 'supported', days_left: 2053 },
      pending_updates: { total: 31, security: 4 },
      packages: 641,
      by_ecosystem: { rpm: 641 },
      app_hits: [],
      osv: { ecosystem: 'Rocky Linux:9', queried: 641, packages: [{ name: 'kernel', version: '5.14.0-427', ids: ['RLSA-2024:5101'], cves: ['CVE-2024-26930'], kev: [], severity: 'high', summary: 'kernel security update' }] },
      kev_count: 0,
      notes: [],
    },
    hardening: {
      os_family: 'linux',
      pass: 20,
      fail: 2,
      na: 2,
      error: 0,
      score: 80,
      needs_admin: [],
      results: [
        hardeningResult('lin.updates.dnf_automatic', '已開啟 dnf-automatic 自動更新', 'medium', 'fail', 'disabled', '= enabled', 'dnf install dnf-automatic && systemctl enable --now dnf-automatic-install.timer', 'update'),
        hardeningResult('lin.audit.auditd', 'auditd 稽核服務在執行', 'low', 'fail', 'inactive', '= active', 'dnf install audit', 'logging'),
        hardeningResult('lin.mac.enforcing', 'AppArmor 或 SELinux 已啟用', 'medium', 'pass', 'selinux', 'in apparmor, selinux', '', 'hardening'),
      ],
    },
    connections: [
      { local_ip: '192.0.2.40', local_port: 5432, remote_ip: '192.0.2.21', remote_port: 48211, direction: 'inbound', process: { pid: 991, name: 'postgres' }, verdict: { level: 'safe', reasons: [{ type: 'private_network' }] } },
    ],
    listeners: [{ proto: 'tcp', bind_ip: '0.0.0.0', port: 5432, process: { pid: 991, name: 'postgres' }, exposed: true, reachability: { state: 'open' } }],
  },
  {
    hostname: 'fin-laptop-07',
    os: { family: 'windows', name: 'Microsoft Windows 11 Enterprise', version: '23H2', build: '22631', kernel: '22631' },
    ip: '192.0.2.77',
    elevated: false,
    score: { overall: 38, connections: 25, exposure: 90, vulns: 40, hardening: 62 },
    findings: [
      {
        scanner: 'intel',
        rule: 'intel.outbound_match',
        severity: 'critical',
        title: '連到威脅情資列名的 IP：203.0.113.66',
        detail: 'updater.exe（暫存目錄）↔ 203.0.113.66:443（判定：危險）。來源：abuse.ch Feodo Tracker（CC0 1.0，90%）',
        key: '203.0.113.66',
        evidence: { type: 'connection', remote_ip: '203.0.113.66', remote_port: 443, direction: 'outbound', process: { pid: 4242, name: 'updater.exe', exe: 'C:\\Users\\finance\\AppData\\Local\\Temp\\updater.exe' } },
        intel_hits: [hit('feodo', '203.0.113.66')],
        recommendation: '隔離主機、結束 updater.exe、封鎖 203.0.113.66，並用防毒完整掃描。',
        actions: [{ kind: 'block_ip', params: { ip: '203.0.113.66', direction: 'outbound' }, requires_elevation: true, destructive: false, reversible: true, description: 'Block 203.0.113.66 outbound' }],
        tags: ['c2'],
      },
      {
        scanner: 'vuln',
        rule: 'vuln.app.7zip-cve-2025-0411',
        severity: 'critical',
        title: '7-Zip 24.08 (x64) 有已知漏洞（CVE-2025-0411）',
        detail: 'Mark-of-the-Web bypass, exploited in the wild',
        key: '7-Zip 24.08 (x64)|24.08',
        evidence: { type: 'package', ecosystem: 'app', name: '7-Zip 24.08 (x64)', version: '24.08', fixed_version: '24.09' },
        recommendation: '更新 7-Zip 到 24.09 以上',
        refs: ['https://nvd.nist.gov/vuln/detail/CVE-2025-0411'],
        tags: ['kev'],
      },
      {
        scanner: 'hardening',
        rule: 'hardening.win.bitlocker.system',
        severity: 'high',
        title: '未通過：系統磁碟已用 BitLocker／裝置加密保護',
        key: 'win.bitlocker.system',
        evidence: { type: 'policy', policy_id: 'win.bitlocker.system', check: 'BitLocker', observed: 'off', expected: '= on', result: 'fail' },
        recommendation: '設定 → 隱私權與安全性 → 裝置加密',
        tags: ['encryption'],
      },
      {
        scanner: 'events',
        rule: 'events.crash.bugcheck',
        severity: 'high',
        title: '藍屏 0x00000124 WHEA_UNCORRECTABLE_ERROR',
        key: 'bugcheck-0x124',
        evidence: { type: 'crash', kind: 'bugcheck', time: iso(1440), code: '0x00000124', name: 'WHEA_UNCORRECTABLE_ERROR', params: [] },
        recommendation: '還原 BIOS 預設（關超頻）、更新 BIOS 與晶片組驅動、跑記憶體測試',
        tags: ['crash'],
      },
    ],
    vuln: {
      os: { family: 'windows', name: 'Microsoft Windows 11 Enterprise', version: '23H2', build: 22631 },
      support: { product: 'Windows 11 23H2', eol: '2026-11-10', status: 'ending_soon', days_left: 24 },
      last_patch: { date: iso(60 * 24 * 52).slice(0, 10), id: 'KB5044285', days: 52 },
      packages: 163,
      by_ecosystem: { windows: 163 },
      app_hits: [
        { rule_id: '7zip-cve-2025-0411', app: '7-Zip', installed_name: '7-Zip 24.08 (x64)', installed: '24.08', fixed: '24.09', cves: ['CVE-2025-0411'], kev: ['CVE-2025-0411'], severity: 'critical', eol: false, summary: 'Mark-of-the-Web bypass in archive extraction, exploited in the wild.', fix: 'Update 7-Zip to 24.09 or later.', reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0411' },
        { rule_id: 'python-eol', app: 'Python', installed_name: 'Python 3.10.11 (64-bit)', installed: '3.10.11150.0', fixed: '3.11.0', cves: [], kev: [], severity: 'low', eol: true, summary: 'Python 3.10 no longer receives security fixes.', fix: 'Install a supported Python and remove 3.10.', reference: 'https://devguide.python.org/versions/' },
      ],
      kev_count: 1,
      notes: [],
    },
    hardening: {
      os_family: 'windows',
      pass: 14,
      fail: 4,
      na: 2,
      error: 0,
      score: 62,
      needs_admin: [],
      results: [
        hardeningResult('win.bitlocker.system', '系統磁碟已用 BitLocker／裝置加密保護', 'high', 'fail', 'off', '= on', '設定 → 隱私權與安全性 → 裝置加密', 'encryption'),
        hardeningResult('win.lsa.protection', 'LSA 保護（RunAsPPL）已開啟', 'medium', 'fail', '', 'in 1, 2', 'Windows 安全性 → 裝置安全性 → 核心隔離', 'credential'),
        hardeningResult('win.llmnr.disabled', 'LLMNR 名稱解析已關閉', 'low', 'fail', '', '= 0', '群組原則「關閉多點傳送名稱解析」', 'network'),
        hardeningResult('win.autorun.disabled', '所有磁碟機的自動執行（AutoRun）已關閉', 'low', 'fail', 'on', '= off', 'NoDriveTypeAutoRun=255', 'device'),
        hardeningResult('win.defender.realtime', 'Microsoft Defender 即時保護已開啟', 'high', 'pass', 'on', '= on', '', 'malware'),
        hardeningResult('win.uac.enabled', '使用者帳戶控制（UAC）已開啟', 'high', 'pass', '1', '= 1', '', 'account'),
      ],
    },
    events: {
      platform: 'windows',
      days: 7,
      events_read: 1980,
      counts_by_level: { critical: 1, error: 37, warning: 210 },
      crash_counts: { bugcheck: 1, app_crash: 2 },
      crashes: [
        { kind: 'bugcheck', time: iso(1440), code: '0x00000124', name: 'WHEA_UNCORRECTABLE_ERROR', params: ['0x0', '0xffffd38f'], likely_causes: ['CPU or memory hardware error', 'Overclocking / unstable voltage'], remediation: 'Restore BIOS defaults, update BIOS and chipset drivers, run a memory test', source: 'System/Microsoft-Windows-Kernel-Power#41' },
        { kind: 'app_crash', time: iso(200), code: '0xc0000005', name: 'EXCEL.EXE', module: 'mso30win32client.dll', process: 'EXCEL.EXE', source: 'Application/Application Error#1000' },
      ],
      security: [{ rule: 'service_installed', severity: 'medium', count: 1, first: iso(900), last: iso(900), detail: 'UpdaterSvc → C:\\Users\\finance\\AppData\\Local\\Temp\\updater.exe' }],
      top_error_sources: [],
      needs_admin: ['Security'],
      notes: [],
    },
    connections: [
      { local_ip: '192.0.2.77', remote_ip: '203.0.113.66', remote_port: 443, process: { pid: 4242, name: 'updater.exe', exe: 'C:\\Users\\finance\\AppData\\Local\\Temp\\updater.exe' }, geo: { country: 'NL', asn: 64500, org: 'Example Hosting' }, verdict: { level: 'dangerous', reasons: [{ type: 'anomaly', kind: 'temp_dir_process', detail: 'C:\\Users\\finance\\AppData\\Local\\Temp\\updater.exe' }, { type: 'intel_hit', ...hit('feodo', '203.0.113.66') }] } },
      { local_ip: '192.0.2.77', remote_ip: '198.51.100.80', remote_port: 8443, process: { pid: 5120, name: 'powershell.exe' }, geo: { country: 'SG', org: 'Example VPS' }, verdict: { level: 'suspicious', reasons: [{ type: 'anomaly', kind: 'shell_with_network', detail: 'powershell.exe' }, { type: 'intel_hit', ...hit('cins', '198.51.100.80') }] } },
      { local_ip: '192.0.2.77', remote_ip: '203.0.113.20', remote_port: 443, process: { pid: 7712, name: 'msedge.exe' }, geo: { country: 'US', org: 'Example CDN' }, verdict: { level: 'safe', reasons: [{ type: 'known_good', list: 'cdn' }] } },
      { local_ip: '192.0.2.77', remote_ip: '203.0.113.30', remote_port: 443, process: { pid: 6020, name: 'Teams.exe' }, geo: { country: 'US', org: 'Example SaaS' }, verdict: { level: 'unknown', reasons: [] } },
    ],
    listeners: [],
  },
  {
    hostname: 'design-mac-03',
    os: { family: 'macos', name: 'macOS', version: '15.1', kernel: '24.1.0' },
    ip: '192.0.2.93',
    elevated: false,
    score: { overall: 88, connections: 95, exposure: 100, vulns: 86, hardening: 73 },
    findings: [
      {
        scanner: 'hardening',
        rule: 'hardening.mac.firewall.stealth',
        severity: 'low',
        title: '未通過：防火牆隱形模式已開啟',
        key: 'mac.firewall.stealth',
        evidence: { type: 'policy', policy_id: 'mac.firewall.stealth', check: 'stealth mode', observed: 'off', expected: 'in on, enabled', result: 'fail' },
        recommendation: '系統設定 → 網路 → 防火牆 → 選項 → 開啟隱形模式',
        tags: ['network'],
      },
      {
        scanner: 'vuln',
        rule: 'vuln.app.chrome-cve-2025-6554',
        severity: 'high',
        title: 'Google Chrome 137.0.7151.120 有已知漏洞（CVE-2025-6554）',
        key: 'Google Chrome|137.0.7151.120',
        evidence: { type: 'package', ecosystem: 'app', name: 'Google Chrome', version: '137.0.7151.120', fixed_version: '138.0.7204.96' },
        recommendation: '重新啟動 Chrome 套用更新',
        refs: ['https://nvd.nist.gov/vuln/detail/CVE-2025-6554'],
      },
    ],
    vuln: {
      os: { family: 'macos', name: 'macOS', version: '15.1' },
      support: { product: 'macOS 15.1', eol: null, status: 'unknown', days_left: null },
      packages: 94,
      by_ecosystem: { 'macos-app': 71, brew: 23 },
      app_hits: [{ rule_id: 'chrome-cve-2025-6554', app: 'Google Chrome', installed_name: 'Google Chrome', installed: '137.0.7151.120', fixed: '138.0.7204.96', cves: ['CVE-2025-6554'], kev: [], severity: 'high', eol: false, summary: 'Type confusion in V8.', fix: 'Restart Chrome to apply the update.', reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-6554' }],
      kev_count: 0,
      notes: [],
    },
    hardening: {
      os_family: 'macos',
      pass: 11,
      fail: 2,
      na: 2,
      error: 0,
      score: 73,
      needs_admin: ['mac.remote_login', 'mac.sudo.nopasswd'],
      results: [
        hardeningResult('mac.firewall.stealth', '防火牆隱形模式已開啟', 'low', 'fail', 'off', 'in on, enabled', '系統設定 → 網路 → 防火牆 → 選項 → 開啟隱形模式', 'network'),
        hardeningResult('mac.login.password_hints', '登入畫面不顯示密碼提示', 'low', 'fail', '3', '= 0', 'RetriesUntilHint -int 0', 'account'),
        hardeningResult('mac.filevault', 'FileVault 磁碟加密已開啟', 'high', 'pass', 'On', '= on', '', 'encryption'),
        hardeningResult('mac.gatekeeper', 'Gatekeeper 已開啟', 'high', 'pass', 'enabled', '= enabled', '', 'malware'),
      ],
    },
    connections: [
      { local_ip: '192.0.2.93', remote_ip: '203.0.113.45', remote_port: 443, process: { pid: 880, name: 'Figma' }, geo: { country: 'US', org: 'Example SaaS' }, verdict: { level: 'unknown', reasons: [] } },
      { local_ip: '192.0.2.93', remote_ip: '203.0.113.20', remote_port: 443, process: { pid: 702, name: 'Google Chrome' }, geo: { country: 'US', org: 'Example CDN' }, verdict: { level: 'safe', reasons: [{ type: 'known_good', list: 'cdn' }] } },
    ],
    listeners: [],
  },
];

// ---------------- 送出 ----------------
async function call(path, { token, body, agentId, agentToken, method = 'POST' } = {}) {
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${token}` };
  if (agentId) headers['x-asa-agent-id'] = agentId;
  if (agentToken) headers['x-asa-agent-token'] = agentToken;
  const r = await fetch(`${HUB}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  if (!r.ok) throw new Error(`${path} → HTTP ${r.status}: ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : {};
}

const { key } = await call('/api/v1/admin/enroll-keys', { token: ADMIN, body: { name: 'demo hosts' } });
for (const h of HOSTS) {
  const agentId = uuid(`demo|${h.hostname}`);
  const agentToken = `demo-${hex(h.hostname, 32)}`;
  const agent = {
    id: agentId,
    version: '0.1.0',
    hostname: h.hostname,
    os: h.os,
    arch: h.os.family === 'macos' ? 'aarch64' : 'x86_64',
    ips: [h.ip],
    uptime_s: 86_400 * 3,
    elevated: h.elevated,
    scanners_available: ['connections', 'intel', 'firewall', 'ports', 'events', 'vuln', 'hardening'],
  };
  await call('/api/v1/agents/register', { token: key, agentId, agentToken, body: { agent, accept_remote_actions: h.hostname === 'fin-laptop-07', service_mode: true } });
  const findings = h.findings.map((f) => finding(h.hostname, f));
  for (let i = 5; i >= 0; i--) {
    const drift = i * 3;
    const s = h.score;
    const clamp = (v) => Math.max(0, Math.min(100, Math.round(v)));
    const report = {
      schema_version: 1,
      report_id: uuid(`report|${h.hostname}|${i}`),
      agent,
      started_at: iso(i * 60 + 2),
      finished_at: iso(i * 60),
      scanners_run: ['connections', 'intel', 'firewall', 'ports', 'events', 'vuln', 'hardening'],
      warnings: [],
      // 越舊的報告問題越少：最新一份才出現危險連線，趨勢圖看得出變化
      findings: i === 0 ? findings : findings.filter((f) => f.scanner !== 'intel'),
      inventory: { packages: h.vuln.packages, by_ecosystem: h.vuln.by_ecosystem, listeners: h.listeners.length, connections: h.connections.length, processes_with_network: h.connections.length },
      summaries: { vuln: h.vuln, hardening: h.hardening, ...(h.events ? { events: h.events } : {}) },
      score: i === 0 ? s : { overall: clamp(s.overall + drift + (h.hostname === 'fin-laptop-07' ? 25 : 0)), connections: clamp(s.connections + (h.hostname === 'fin-laptop-07' ? 60 : drift)), exposure: s.exposure, vulns: s.vulns, hardening: clamp(s.hardening - i) },
      partial: !h.elevated,
    };
    await call('/api/v1/ingest/report', { token: key, agentId, agentToken, body: report });
  }
  await call('/api/v1/ingest/snapshot', {
    token: key,
    agentId,
    agentToken,
    body: { agent_id: agentId, ts: iso(1), connections: h.connections.map(conn), listeners: h.listeners },
  });
  console.log(`seeded ${h.hostname} (${agentId})`);
}
console.log('done');
