// 繁中原文 → 英文。key 一律用單引號（scripts/i18n-scan.mjs 會比對頁面裡的 t('…') 是否都有收錄）。
export const en: Record<string, string> = {
  // ---- layout ----
  'ai-security-agent 的中央儀表板：連線判定、威脅情資、防火牆、漏洞與 AI 分析':
    'Central dashboard for ai-security-agent: connection verdicts, threat intel, firewall, vulnerabilities and AI analysis',
  '切換語言': 'Switch language',
  '深色／淺色': 'Dark / light',
  '登出': 'Sign out',
  '開放模式（僅本機）': 'Open mode (local only)',
  '唯讀檢視': 'Read-only view',
  '管理員': 'Administrator',
  '總覽': 'Overview',

  // ---- overview ----
  '所有端點的連線判定、威脅情資命中與弱點，集中在這裡。':
    'Connection verdicts, threat-intel hits and weaknesses from every endpoint, in one place.',
  '代理程式': 'Agents',
  '尚未有端點回報': 'No endpoint has reported yet',
  '版本': 'Version',
  '伺服器版': 'Server edition',
  '單機版': 'Standalone edition',
  '資料庫': 'Database',
  '正常（{ms} ms）': 'OK ({ms} ms)',
  '未設定 ASA_HUB_DATABASE_URL': 'ASA_HUB_DATABASE_URL is not set',
  '無法連線': 'Unreachable',
  '存取模式': 'Access mode',
  '需要金鑰': 'Key required',
  '還沒有任何代理程式回報': 'No agent has reported yet',
  '在要保護的電腦上安裝 asa，然後執行：': 'Install asa on the machine you want to protect, then run:',

  '線上 {online}、延遲 {stale}、離線 {offline}': 'Online {online}, stale {stale}, offline {offline}',
  '危險連線': 'Dangerous connections',
  '另有 {n} 條可疑': 'plus {n} suspicious',
  '未處理的發現': 'Open findings',
  '查看各代理程式 →': 'View agents →',

  // ---- severity ----
  '嚴重': 'critical',
  '高': 'high',
  '中': 'medium',
  '低': 'low',
  '資訊': 'info',

  // ---- agents ----
  '每台安裝 asa 並註冊到這個 Hub 的電腦或伺服器。': 'Every computer or server running asa that is enrolled in this hub.',
  '線上': 'Online',
  '延遲': 'Stale',
  '離線': 'Offline',
  '部分資料': 'Partial data',
  '主機': 'Host',
  '狀態': 'Status',
  '系統': 'System',
  '分數': 'Score',
  '最後回報': 'Last seen',
  '{n} 秒前': '{n}s ago',
  '{n} 分鐘前': '{n} min ago',
  '{n} 小時前': '{n} h ago',
  '{n} 天前': '{n} d ago',

  // ---- login ----
  '貼上管理員金鑰（ASA_HUB_ADMIN_SECRET）登入': 'Paste the administrator key (ASA_HUB_ADMIN_SECRET) to sign in',
  '嘗試太多次，請一分鐘後再試': 'Too many attempts; try again in a minute',
  '金鑰不正確': 'Wrong key',
  '登入失敗（{status}）': 'Sign-in failed ({status})',
  '管理員金鑰': 'Administrator key',
  '登入中…': 'Signing in…',
  '登入': 'Sign in',
};
