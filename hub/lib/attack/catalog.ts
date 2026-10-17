// MITRE ATT&CK® 技術與戰術（只列我們的對應表會用到的），以及法規／框架的控制項名稱。
// 技術 ID 與英文名稱出自 MITRE ATT&CK（© The MITRE Corporation，依其使用條款引用並標註）；中文名稱與白話說明是我們自己寫的。
// 法規控制項只列編號與我們自己寫的短標題（不收錄標準原文）。這些是「參考對應」，不等於稽核或認證。

export const TACTICS = [
  { id: 'reconnaissance', zh: '偵察', en: 'Reconnaissance' },
  { id: 'initial-access', zh: '初始入侵', en: 'Initial Access' },
  { id: 'execution', zh: '執行', en: 'Execution' },
  { id: 'persistence', zh: '常駐', en: 'Persistence' },
  { id: 'privilege-escalation', zh: '提權', en: 'Privilege Escalation' },
  { id: 'defense-evasion', zh: '躲避防禦', en: 'Defense Evasion' },
  { id: 'credential-access', zh: '竊取帳密', en: 'Credential Access' },
  { id: 'discovery', zh: '探查環境', en: 'Discovery' },
  { id: 'lateral-movement', zh: '橫向移動', en: 'Lateral Movement' },
  { id: 'collection', zh: '蒐集資料', en: 'Collection' },
  { id: 'command-and-control', zh: '遠端控制', en: 'Command and Control' },
  { id: 'impact', zh: '破壞', en: 'Impact' },
] as const;
export type TacticId = (typeof TACTICS)[number]['id'];

export interface Technique {
  en: string;
  zh: string;
  tactics: TacticId[];
  /** 一句白話：攻擊者在做什麼。 */
  hint: string;
}

export const TECHNIQUES: Record<string, Technique> = {
  T1003: { en: 'OS Credential Dumping', zh: '從系統撈帳號密碼', tactics: ['credential-access'], hint: '從記憶體或系統檔案取出登入憑證' },
  'T1003.001': { en: 'LSASS Memory', zh: '從 LSASS 撈密碼', tactics: ['credential-access'], hint: '讀取 Windows 登入服務的記憶體拿到密碼或雜湊' },
  T1021: { en: 'Remote Services', zh: '遠端服務登入', tactics: ['lateral-movement'], hint: '用合法的遠端服務登入其他電腦' },
  'T1021.001': { en: 'Remote Desktop Protocol', zh: '遠端桌面', tactics: ['lateral-movement'], hint: '用遠端桌面（RDP）登入' },
  'T1021.004': { en: 'SSH', zh: 'SSH 登入', tactics: ['lateral-movement'], hint: '用 SSH 登入' },
  T1040: { en: 'Network Sniffing', zh: '竊聽網路', tactics: ['credential-access', 'discovery'], hint: '攔截網路上沒加密的流量取得帳密' },
  T1046: { en: 'Network Service Discovery', zh: '掃描網路服務', tactics: ['discovery'], hint: '掃描哪些電腦開了哪些服務' },
  T1053: { en: 'Scheduled Task/Job', zh: '排程工作', tactics: ['execution', 'persistence', 'privilege-escalation'], hint: '用排程讓惡意程式定時執行' },
  'T1053.005': { en: 'Scheduled Task', zh: 'Windows 排程工作', tactics: ['execution', 'persistence', 'privilege-escalation'], hint: '建立 Windows 排程工作讓程式定時或開機執行' },
  T1059: { en: 'Command and Scripting Interpreter', zh: '命令列與腳本', tactics: ['execution'], hint: '用 PowerShell、cmd、bash 等執行指令' },
  'T1059.001': { en: 'PowerShell', zh: 'PowerShell', tactics: ['execution'], hint: '用 PowerShell 執行指令（舊版 2.0 沒有記錄與防護）' },
  T1068: { en: 'Exploitation for Privilege Escalation', zh: '利用漏洞提權', tactics: ['privilege-escalation'], hint: '利用系統沒修的漏洞取得管理員權限' },
  T1070: { en: 'Indicator Removal', zh: '湮滅證據', tactics: ['defense-evasion'], hint: '刪除紀錄掩蓋行蹤' },
  'T1070.001': { en: 'Clear Windows Event Logs', zh: '清除事件記錄', tactics: ['defense-evasion'], hint: '清空 Windows 事件記錄' },
  T1071: { en: 'Application Layer Protocol', zh: '透過一般協定遠端控制', tactics: ['command-and-control'], hint: '把控制指令藏在 HTTP、DNS 等一般流量裡' },
  T1078: { en: 'Valid Accounts', zh: '使用合法帳號', tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'], hint: '用偷來或預設的帳號登入' },
  'T1078.001': { en: 'Default Accounts', zh: '預設帳號', tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'], hint: '用系統內建的 Guest、Administrator 等帳號' },
  'T1078.003': { en: 'Local Accounts', zh: '本機帳號', tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'], hint: '用這台電腦上的本機帳號（含 root）' },
  T1091: { en: 'Replication Through Removable Media', zh: '透過隨身碟散播', tactics: ['initial-access', 'lateral-movement'], hint: '插入隨身碟就自動執行惡意程式' },
  T1098: { en: 'Account Manipulation', zh: '竄改帳號', tactics: ['persistence', 'privilege-escalation'], hint: '啟用或修改帳號留後門' },
  T1110: { en: 'Brute Force', zh: '暴力破解', tactics: ['credential-access'], hint: '大量嘗試密碼' },
  T1112: { en: 'Modify Registry', zh: '修改登錄', tactics: ['defense-evasion', 'persistence'], hint: '改 Windows 登錄關掉防護或常駐' },
  'T1136.001': { en: 'Create Account: Local Account', zh: '新增本機帳號', tactics: ['persistence'], hint: '偷偷建一個本機帳號當後門' },
  T1133: { en: 'External Remote Services', zh: '對外開放的遠端服務', tactics: ['initial-access', 'persistence'], hint: '從網路直接連進對外開放的遠端服務' },
  T1190: { en: 'Exploit Public-Facing Application', zh: '攻擊對外服務的漏洞', tactics: ['initial-access'], hint: '利用對外開放服務的漏洞入侵' },
  T1203: { en: 'Exploitation for Client Execution', zh: '利用軟體漏洞執行', tactics: ['execution'], hint: '利用瀏覽器、文件軟體等的漏洞執行惡意程式' },
  'T1204.002': { en: 'User Execution: Malicious File', zh: '誘騙執行惡意檔案', tactics: ['execution'], hint: '騙使用者打開惡意檔案' },
  T1210: { en: 'Exploitation of Remote Services', zh: '利用遠端服務漏洞', tactics: ['lateral-movement'], hint: '利用 SMB 等內網服務的漏洞擴散' },
  T1498: { en: 'Network Denial of Service', zh: '網路阻斷服務', tactics: ['impact'], hint: '用大量流量癱瘓服務' },
  'T1542.003': { en: 'Bootkit', zh: '開機程式感染', tactics: ['persistence', 'defense-evasion'], hint: '在作業系統載入前就先執行惡意程式' },
  'T1548.002': { en: 'Bypass User Account Control', zh: '繞過 UAC', tactics: ['privilege-escalation', 'defense-evasion'], hint: '不跳出 UAC 提示就取得管理員權限' },
  'T1548.003': { en: 'Sudo and Sudo Caching', zh: '濫用 sudo', tactics: ['privilege-escalation', 'defense-evasion'], hint: '利用不用密碼的 sudo 取得 root' },
  'T1553.001': { en: 'Gatekeeper Bypass', zh: '繞過 Gatekeeper', tactics: ['defense-evasion'], hint: '讓 macOS 不檢查就執行下載的程式' },
  'T1553.005': { en: 'Mark-of-the-Web Bypass', zh: '繞過下載標記', tactics: ['defense-evasion'], hint: '讓下載的檔案不被 SmartScreen 檢查' },
  T1557: { en: 'Adversary-in-the-Middle', zh: '中間人攻擊', tactics: ['credential-access', 'collection'], hint: '假冒網路設備攔截流量' },
  'T1557.001': { en: 'LLMNR/NBT-NS Poisoning and SMB Relay', zh: 'LLMNR 投毒', tactics: ['credential-access', 'collection'], hint: '假冒區網名稱解析騙取帳密雜湊' },
  'T1562.001': { en: 'Disable or Modify Tools', zh: '關閉防毒或防護工具', tactics: ['defense-evasion'], hint: '關掉 Defender 等防護' },
  'T1562.004': { en: 'Disable or Modify System Firewall', zh: '關閉或放寬防火牆', tactics: ['defense-evasion'], hint: '關掉防火牆或加放行規則' },
  'T1562.012': { en: 'Disable or Modify Linux Audit System', zh: '關閉 Linux 稽核', tactics: ['defense-evasion'], hint: '停掉 auditd 不留紀錄' },
  T1571: { en: 'Non-Standard Port', zh: '非標準 port 通訊', tactics: ['command-and-control'], hint: '用少見的 port 跟控制伺服器通訊' },
  T1595: { en: 'Active Scanning', zh: '主動掃描', tactics: ['reconnaissance'], hint: '從外面掃描找可以攻擊的目標' },
  'T1574.007': { en: 'Path Interception by PATH Environment Variable', zh: '劫持 PATH', tactics: ['persistence', 'privilege-escalation', 'defense-evasion'], hint: '在 PATH 裡可寫的目錄放同名惡意程式' },
};

/** 法規／框架。 */
export const FRAMEWORKS = [
  { id: 'iso27001', zh: 'ISO/IEC 27001:2022 附錄 A', en: 'ISO/IEC 27001:2022 Annex A', short: 'ISO 27001' },
  { id: 'nist800-53', zh: 'NIST SP 800-53 Rev. 5', en: 'NIST SP 800-53 Rev. 5', short: 'NIST 800-53' },
  { id: 'pci4', zh: 'PCI DSS v4.0', en: 'PCI DSS v4.0', short: 'PCI DSS 4' },
  { id: 'cis8', zh: 'CIS Controls v8', en: 'CIS Controls v8', short: 'CIS v8' },
] as const;
export type FrameworkId = (typeof FRAMEWORKS)[number]['id'];

/** 控制項短標題（我們自己寫的摘要）；key 是 `框架:編號`。 */
export const CONTROLS: Record<string, { zh: string; en: string }> = {
  'iso27001:A.5.15': { zh: '存取控制', en: 'Access control' },
  'iso27001:A.7.10': { zh: '儲存媒體', en: 'Storage media' },
  'iso27001:A.8.2': { zh: '特權存取', en: 'Privileged access rights' },
  'iso27001:A.8.5': { zh: '安全的身分驗證', en: 'Secure authentication' },
  'iso27001:A.8.7': { zh: '防範惡意軟體', en: 'Protection against malware' },
  'iso27001:A.8.8': { zh: '技術漏洞管理', en: 'Management of technical vulnerabilities' },
  'iso27001:A.8.9': { zh: '組態管理', en: 'Configuration management' },
  'iso27001:A.8.15': { zh: '日誌記錄', en: 'Logging' },
  'iso27001:A.8.16': { zh: '監控活動', en: 'Monitoring activities' },
  'iso27001:A.8.20': { zh: '網路安全', en: 'Networks security' },
  'iso27001:A.8.24': { zh: '使用密碼學', en: 'Use of cryptography' },
  'nist800-53:AC-2': { zh: '帳號管理', en: 'Account management' },
  'nist800-53:AC-6': { zh: '最小權限', en: 'Least privilege' },
  'nist800-53:AC-7': { zh: '登入失敗次數限制', en: 'Unsuccessful logon attempts' },
  'nist800-53:AC-17': { zh: '遠端存取', en: 'Remote access' },
  'nist800-53:AU-9': { zh: '保護稽核紀錄', en: 'Protection of audit information' },
  'nist800-53:AU-12': { zh: '產生稽核紀錄', en: 'Audit record generation' },
  'nist800-53:CM-6': { zh: '組態設定', en: 'Configuration settings' },
  'nist800-53:CM-7': { zh: '最少功能', en: 'Least functionality' },
  'nist800-53:IA-5': { zh: '驗證資訊管理', en: 'Authenticator management' },
  'nist800-53:MP-7': { zh: '媒體使用', en: 'Media use' },
  'nist800-53:RA-5': { zh: '弱點監控與掃描', en: 'Vulnerability monitoring and scanning' },
  'nist800-53:SA-22': { zh: '不再支援的元件', en: 'Unsupported system components' },
  'nist800-53:SC-7': { zh: '邊界防護', en: 'Boundary protection' },
  'nist800-53:SC-28': { zh: '靜態資料保護', en: 'Protection of information at rest' },
  'nist800-53:SI-2': { zh: '修補缺陷', en: 'Flaw remediation' },
  'nist800-53:SI-3': { zh: '惡意程式防護', en: 'Malicious code protection' },
  'nist800-53:SI-4': { zh: '系統監控', en: 'System monitoring' },
  'nist800-53:SI-7': { zh: '軟體與韌體完整性', en: 'Software, firmware, and information integrity' },
  'pci4:1.2.1': { zh: '網路安全控制的設定標準', en: 'Network security control configuration standards' },
  'pci4:2.2.1': { zh: '系統元件的設定標準', en: 'System component configuration standards' },
  'pci4:2.2.2': { zh: '廠商預設帳號', en: 'Vendor default accounts' },
  'pci4:2.2.4': { zh: '只啟用必要的服務', en: 'Only necessary services enabled' },
  'pci4:5.2.1': { zh: '部署防毒', en: 'Anti-malware deployed' },
  'pci4:5.3.1': { zh: '防毒保持更新', en: 'Anti-malware kept current' },
  'pci4:6.3.3': { zh: '安裝安全更新', en: 'Security patches installed' },
  'pci4:8.3.4': { zh: '登入失敗鎖定', en: 'Lockout after invalid attempts' },
  'pci4:10.2.1': { zh: '啟用稽核紀錄', en: 'Audit logs enabled' },
  'pci4:10.3.2': { zh: '稽核紀錄防竄改', en: 'Audit logs protected from modification' },
  'pci4:11.5.1': { zh: '入侵偵測', en: 'Intrusion detection' },
  'cis8:2.2': { zh: '軟體仍在支援期', en: 'Authorized software is supported' },
  'cis8:3.6': { zh: '加密使用者裝置', en: 'Encrypt data on end-user devices' },
  'cis8:4.1': { zh: '安全設定流程', en: 'Secure configuration process' },
  'cis8:4.4': { zh: '伺服器防火牆', en: 'Firewall on servers' },
  'cis8:4.5': { zh: '使用者裝置防火牆', en: 'Firewall on end-user devices' },
  'cis8:4.7': { zh: '管理預設帳號', en: 'Manage default accounts' },
  'cis8:4.8': { zh: '關閉不需要的服務', en: 'Disable unnecessary services' },
  'cis8:5.4': { zh: '限制管理員權限', en: 'Restrict administrator privileges' },
  'cis8:7.3': { zh: '自動更新作業系統', en: 'Automated OS patch management' },
  'cis8:7.4': { zh: '自動更新應用程式', en: 'Automated application patch management' },
  'cis8:8.2': { zh: '收集稽核紀錄', en: 'Collect audit logs' },
  'cis8:10.1': { zh: '部署防毒', en: 'Deploy anti-malware' },
  'cis8:10.2': { zh: '防毒特徵自動更新', en: 'Automatic anti-malware signature updates' },
  'cis8:10.3': { zh: '關閉自動播放', en: 'Disable autorun for removable media' },
  'cis8:13.1': { zh: '集中安全告警', en: 'Centralize security event alerting' },
};

export function frameworkOf(control: string): FrameworkId | null {
  const f = control.split(':')[0];
  return FRAMEWORKS.some((x) => x.id === f) ? (f as FrameworkId) : null;
}

/** `T1110` → https://attack.mitre.org/techniques/T1110/；子技術 `T1053.005` → /T1053/005/。 */
export function techniqueUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}
