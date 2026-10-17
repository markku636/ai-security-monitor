// 問題（finding）的規則 → MITRE ATT&CK 技術＋法規控制項。對應表是我們自己依規則內容寫的（參考用，不等於稽核認證）。
// 在 Hub 端對應（用 finding 的 rule），所以舊版 agent 的問題也有標籤，改對應表立刻生效、不用重新掃描。
import { findings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';

// 常用的控制項組合
const C = {
  malware: ['iso27001:A.8.7', 'nist800-53:SI-3', 'pci4:5.2.1', 'pci4:5.3.1', 'cis8:10.1', 'cis8:10.2'],
  patch: ['iso27001:A.8.8', 'nist800-53:SI-2', 'nist800-53:RA-5', 'pci4:6.3.3', 'cis8:7.3', 'cis8:7.4'],
  eol: ['iso27001:A.8.8', 'nist800-53:SA-22', 'pci4:6.3.3', 'cis8:2.2'],
  config: ['iso27001:A.8.9', 'nist800-53:CM-6', 'pci4:2.2.1', 'cis8:4.1'],
  services: ['iso27001:A.8.9', 'nist800-53:CM-7', 'pci4:2.2.4', 'cis8:4.8'],
  firewall: ['iso27001:A.8.20', 'nist800-53:SC-7', 'pci4:1.2.1', 'cis8:4.4', 'cis8:4.5'],
  bruteforce: ['iso27001:A.8.5', 'nist800-53:AC-7', 'pci4:8.3.4'],
  auth: ['iso27001:A.8.5', 'nist800-53:IA-5'],
  accounts: ['iso27001:A.5.15', 'nist800-53:AC-2', 'pci4:2.2.2', 'cis8:4.7'],
  privilege: ['iso27001:A.8.2', 'nist800-53:AC-6', 'cis8:5.4'],
  logging: ['iso27001:A.8.15', 'nist800-53:AU-12', 'pci4:10.2.1', 'cis8:8.2'],
  logTamper: ['iso27001:A.8.15', 'nist800-53:AU-9', 'pci4:10.3.2'],
  monitoring: ['iso27001:A.8.16', 'nist800-53:SI-4', 'pci4:11.5.1', 'cis8:13.1'],
  encryption: ['iso27001:A.8.24', 'nist800-53:SC-28', 'cis8:3.6'],
  remote: ['iso27001:A.8.5', 'nist800-53:AC-17'],
  integrity: ['iso27001:A.8.9', 'nist800-53:SI-7', 'cis8:4.1'],
  fim: ['iso27001:A.8.9', 'nist800-53:SI-7', 'pci4:11.5.2'],
  media: ['iso27001:A.7.10', 'nist800-53:MP-7', 'cis8:10.3'],
};

export interface Mapping {
  mitre: string[];
  compliance: string[];
}

/** 規則樣式：完整名稱，或結尾 `*` 的前綴。 */
export const RULE_MAP: Record<string, Mapping> = {
  // ---- DNS ----
  'dns.intel_domain': { mitre: ['T1071.004'], compliance: C.monitoring },
  'dns.tunnel': { mitre: ['T1572', 'T1048.003'], compliance: C.monitoring },
  'dns.dga': { mitre: ['T1568.002'], compliance: [...C.malware.slice(0, 2), ...C.monitoring.slice(0, 2)] },
  'dns.nxdomain_burst': { mitre: ['T1568.002'], compliance: C.monitoring },
  'dns.doh_bypass': { mitre: ['T1572'], compliance: C.monitoring },
  'dns.tunnel_service': { mitre: ['T1572'], compliance: C.monitoring },
  // ---- 連線 ----
  'connections.beaconing': { mitre: ['T1071'], compliance: C.monitoring },
  'connections.shell_with_network': { mitre: ['T1059'], compliance: C.monitoring },
  'connections.temp_dir_process': { mitre: ['T1204.002'], compliance: [...C.malware.slice(0, 2), ...C.monitoring.slice(0, 2)] },
  'connections.risky_port_outbound': { mitre: ['T1571'], compliance: C.monitoring },
  'connections.risky_port': { mitre: ['T1133'], compliance: [...C.services, ...C.firewall.slice(0, 2)] },
  'connections.exposed_listener': { mitre: ['T1190', 'T1133'], compliance: [...C.services, ...C.firewall.slice(0, 2)] },
  // ---- 情資 ----
  'intel.outbound_match': { mitre: ['T1071'], compliance: C.monitoring },
  'intel.reputation': { mitre: ['T1071'], compliance: C.monitoring },
  'intel.abuseipdb': { mitre: ['T1071'], compliance: C.monitoring },
  'intel.inbound_match': { mitre: ['T1595', 'T1110'], compliance: [...C.monitoring, ...C.firewall.slice(0, 2)] },
  // ---- 對外開放的 port ----
  'ports.exposed_*': { mitre: ['T1190', 'T1133'], compliance: [...C.services, ...C.firewall.slice(0, 3)] },
  // ---- 防火牆 ----
  'firewall.*': { mitre: ['T1562.004'], compliance: C.firewall },
  // ---- 漏洞與更新 ----
  'vuln.os_eol': { mitre: ['T1068', 'T1210'], compliance: C.eol },
  'vuln.os_eol_soon': { mitre: ['T1068'], compliance: C.eol },
  'vuln.updates_stale': { mitre: ['T1068', 'T1210'], compliance: C.patch },
  'vuln.pending_security_updates': { mitre: ['T1068', 'T1210'], compliance: C.patch },
  'vuln.osv_package': { mitre: ['T1203'], compliance: C.patch },
  'vuln.app.*': { mitre: ['T1203'], compliance: C.patch },
  // ---- 事件記錄 ----
  'events.failed_logon_burst': { mitre: ['T1110'], compliance: [...C.bruteforce, ...C.monitoring.slice(0, 2)] },
  'events.ntlm_failure_burst': { mitre: ['T1110'], compliance: [...C.bruteforce, ...C.monitoring.slice(0, 2)] },
  'events.account_locked': { mitre: ['T1110'], compliance: C.bruteforce },
  'events.user_created': { mitre: ['T1136.001'], compliance: [...C.accounts.slice(0, 2), ...C.monitoring.slice(0, 2)] },
  'events.user_enabled': { mitre: ['T1098'], compliance: [...C.accounts.slice(0, 2), ...C.monitoring.slice(0, 2)] },
  'events.audit_log_cleared': { mitre: ['T1070.001'], compliance: C.logTamper },
  'events.defender_disabled': { mitre: ['T1562.001'], compliance: C.malware },
  'events.defender_detection': { mitre: ['T1204.002'], compliance: C.malware },
  'events.remote_logon': { mitre: ['T1021.001'], compliance: [...C.remote, ...C.monitoring.slice(0, 2)] },
  'events.task_created': { mitre: ['T1053.005'], compliance: [...C.integrity.slice(0, 2), ...C.monitoring.slice(0, 2)] },
  // ---- 檔案完整性與開機自啟（fim.<分類>.<變更>）----
  'fim.hosts.*': { mitre: ['T1565.001'], compliance: C.fim },
  'fim.startup.*': { mitre: ['T1547.001'], compliance: C.fim },
  'fim.tasks.*': { mitre: ['T1053.005'], compliance: C.fim },
  'fim.cron.*': { mitre: ['T1053.003'], compliance: C.fim },
  'fim.drivers.*': { mitre: ['T1014', 'T1543.003'], compliance: C.fim },
  'fim.boot.*': { mitre: ['T1542.003'], compliance: C.fim },
  'fim.ssh_keys.*': { mitre: ['T1098.004'], compliance: C.fim },
  'fim.launchd.*': { mitre: ['T1543.001'], compliance: C.fim },
  'fim.systemd.*': { mitre: ['T1543.002'], compliance: C.fim },
  'fim.system_bin.*': { mitre: ['T1554'], compliance: C.fim },
  'fim.profile.*': { mitre: ['T1546.013'], compliance: C.fim },
  'fim.etc_config.*': { mitre: [], compliance: C.fim },
  'fim.custom.*': { mitre: [], compliance: C.fim },
  'fim.many_changes': { mitre: [], compliance: C.fim },
  'fim.autorun.run_key.*': { mitre: ['T1547.001'], compliance: C.fim },
  'fim.autorun.winlogon.*': { mitre: ['T1547.004'], compliance: C.fim },
  'fim.autorun.service.*': { mitre: ['T1543.003'], compliance: C.fim },
  'fim.autorun.systemd.*': { mitre: ['T1543.002'], compliance: C.fim },
  // ---- 安全設定：Windows ----
  'hardening.win.uac.*': { mitre: ['T1548.002'], compliance: [...C.privilege, ...C.config.slice(0, 2)] },
  'hardening.win.defender.*': { mitre: ['T1562.001'], compliance: C.malware },
  'hardening.win.smartscreen': { mitre: ['T1553.005', 'T1204.002'], compliance: C.malware.slice(0, 2) },
  'hardening.win.smb1.*': { mitre: ['T1210'], compliance: C.services },
  'hardening.win.rdp.nla': { mitre: ['T1021.001'], compliance: [...C.remote, ...C.config.slice(0, 2)] },
  'hardening.win.bitlocker.system': { mitre: [], compliance: C.encryption },
  'hardening.win.secureboot': { mitre: ['T1542.003'], compliance: C.integrity },
  'hardening.win.lsa.protection': { mitre: ['T1003.001'], compliance: [...C.auth, ...C.config.slice(0, 2)] },
  'hardening.win.wdigest': { mitre: ['T1003.001'], compliance: [...C.auth, ...C.config.slice(0, 2)] },
  'hardening.win.account.*': { mitre: ['T1078.001'], compliance: C.accounts },
  'hardening.win.update.*': { mitre: ['T1068'], compliance: C.patch },
  'hardening.win.autorun.disabled': { mitre: ['T1091'], compliance: C.media },
  'hardening.win.llmnr.disabled': { mitre: ['T1557.001'], compliance: C.services },
  'hardening.win.powershell_v2.removed': { mitre: ['T1059.001'], compliance: [...C.services, ...C.logging.slice(0, 2)] },
  'hardening.win.remote_registry': { mitre: ['T1112'], compliance: C.services },
  // ---- 安全設定：Linux ----
  'hardening.lin.ssh.root_login': { mitre: ['T1078.003', 'T1021.004'], compliance: [...C.privilege, ...C.remote.slice(1)] },
  'hardening.lin.ssh.password_auth': { mitre: ['T1110', 'T1021.004'], compliance: [...C.auth, ...C.remote.slice(1)] },
  'hardening.lin.ssh.empty_passwords': { mitre: ['T1078'], compliance: C.auth },
  'hardening.lin.ssh.x11_forwarding': { mitre: ['T1021.004'], compliance: C.services },
  'hardening.lin.ssh.max_auth_tries': { mitre: ['T1110'], compliance: C.bruteforce },
  'hardening.lin.ssh.brute_force_guard': { mitre: ['T1110'], compliance: C.bruteforce },
  'hardening.lin.kernel.*': { mitre: ['T1068'], compliance: C.config },
  'hardening.lin.fs.suid_dumpable': { mitre: ['T1003'], compliance: C.config },
  'hardening.lin.fs.*': { mitre: ['T1068'], compliance: C.config },
  'hardening.lin.net.syncookies': { mitre: ['T1498'], compliance: C.config },
  'hardening.lin.net.*': { mitre: ['T1557'], compliance: C.config },
  'hardening.lin.mac.enforcing': { mitre: ['T1562.001'], compliance: C.integrity },
  'hardening.lin.accounts.uid0': { mitre: ['T1078.003'], compliance: [...C.privilege, ...C.accounts.slice(0, 2)] },
  'hardening.lin.accounts.empty_passwords': { mitre: ['T1078'], compliance: C.auth },
  'hardening.lin.sudo.nopasswd': { mitre: ['T1548.003'], compliance: C.privilege },
  'hardening.lin.path.world_writable': { mitre: ['T1574.007'], compliance: C.config },
  'hardening.lin.updates.*': { mitre: ['T1068'], compliance: C.patch },
  'hardening.lin.services.legacy': { mitre: ['T1040', 'T1021'], compliance: C.services },
  'hardening.lin.audit.auditd': { mitre: ['T1562.012'], compliance: C.logging },
  // ---- 安全設定：macOS ----
  'hardening.mac.gatekeeper': { mitre: ['T1553.001'], compliance: C.malware.slice(0, 2) },
  'hardening.mac.sip': { mitre: ['T1562.001'], compliance: C.integrity },
  'hardening.mac.filevault': { mitre: [], compliance: C.encryption },
  'hardening.mac.firewall.*': { mitre: ['T1046'], compliance: C.firewall },
  'hardening.mac.update.*': { mitre: ['T1068'], compliance: C.patch },
  'hardening.mac.login.guest': { mitre: ['T1078.001'], compliance: C.accounts },
  'hardening.mac.login.autologin': { mitre: ['T1078'], compliance: C.auth },
  'hardening.mac.login.password_hints': { mitre: ['T1110'], compliance: C.auth },
  'hardening.mac.screen_lock': { mitre: [], compliance: ['iso27001:A.8.5', 'nist800-53:AC-2'] },
  'hardening.mac.remote_login': { mitre: ['T1021.004'], compliance: [...C.remote, ...C.services.slice(1, 2)] },
  'hardening.mac.sudo.nopasswd': { mitre: ['T1548.003'], compliance: C.privilege },
  'hardening.mac.path.world_writable': { mitre: ['T1574.007'], compliance: C.config },
};

const EXACT = new Map<string, Mapping>();
const PREFIX: [string, Mapping][] = [];
for (const [k, v] of Object.entries(RULE_MAP)) {
  if (k.endsWith('*')) PREFIX.push([k.slice(0, -1), v]);
  else EXACT.set(k, v);
}
// 長的前綴先比（hardening.lin.fs.suid_dumpable 是完整名稱，會先命中 EXACT）
PREFIX.sort((a, b) => b[0].length - a[0].length);

const EMPTY: Mapping = { mitre: [], compliance: [] };

/** 某條規則的對應：完整名稱優先，其次最長的前綴；沒有就空的。 */
export function mapRule(rule: string): Mapping {
  const exact = EXACT.get(rule);
  if (exact) return exact;
  for (const [p, m] of PREFIX) if (rule.startsWith(p)) return m;
  return EMPTY;
}

/** 這條規則有沒有對應到某個技術（含子技術：T1003 也算 T1003.001）。 */
export function ruleHasTechnique(rule: string, id: string): boolean {
  return mapRule(rule).mitre.some((t) => t === id || t.startsWith(`${id}.`));
}

/** 這條規則有沒有對應到某個控制項（`iso27001:A.8.8`），或整個框架（`iso27001`）。 */
export function ruleHasControl(rule: string, control: string): boolean {
  const framework = !control.includes(':');
  return mapRule(rule).compliance.some((c) => (framework ? c.startsWith(`${control}:`) : c === control));
}

/** 資料庫裡出現過、而且符合條件的規則（問題頁的「手法」「法規」篩選用；規則種類不多，先列出再比對最準）。 */
export async function matchingRules(db: DB, pred: (rule: string) => boolean): Promise<string[]> {
  const rows = await db.selectDistinct({ rule: findings.rule }).from(findings);
  return rows.map((r) => r.rule).filter(pred);
}
