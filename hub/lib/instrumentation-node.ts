// instrumentation.ts 的 Node runtime 部分（獨立成檔，edge 編譯時整個略過，不會帶進 node:* 模組）。
export async function registerNode(): Promise<void> {
  // 先裝 TCP 來源位址標頭（自動核准網段只信這個，不信 X-Forwarded-For）
  const { installPeerIpHook } = await import('./peer-ip-hook');
  installPeerIpHook();
  const { env } = await import('./env');
  const e = env();
  if (!e.databaseUrl) {
    console.warn('[ai-security-monitor-hub] AI_SECURITY_MONITOR_HUB_DATABASE_URL (or ASA_HUB_DATABASE_URL) is not set; the hub cannot store data');
    return;
  }
  if (!e.adminSecret) {
    console.warn('[ai-security-monitor-hub] open mode (no AI_SECURITY_MONITOR_HUB_ADMIN_SECRET): everyone is admin — bind to 127.0.0.1 only');
  }
  try {
    const { ensureMigrated } = await import('./db');
    await ensureMigrated();
    console.log('[ai-security-monitor-hub] database ready');
  } catch (err) {
    console.error('[ai-security-monitor-hub] migration failed; will retry on first request', err);
  }
  void startDiscovery();
}

/** 區網 mDNS 廣播（ASA_HUB_MDNS；伺服器版預設開）。需要資料庫裡的 Hub 指紋；失敗只記 log。 */
async function startDiscovery(): Promise<void> {
  try {
    const { mdnsEnabled, startMdns } = await import('./discovery/mdns');
    if (!mdnsEnabled()) return;
    const { getDb } = await import('./db');
    const { hubIdentity, hubInfo } = await import('./enroll/identity');
    startMdns(hubInfo(await hubIdentity(getDb())));
  } catch (err) {
    console.warn('[ai-security-monitor-hub] mDNS advertising not started', err instanceof Error ? err.message : err);
  }
}
