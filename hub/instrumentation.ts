// 伺服器啟動時（Node runtime）先跑 migration；資料庫暫時連不上不擋啟動，/api/health 會回 503。
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;
  const { env } = await import('./lib/env');
  const e = env();
  if (!e.databaseUrl) {
    console.warn('[ai-security-monitor-hub] AI_SECURITY_MONITOR_HUB_DATABASE_URL (or ASA_HUB_DATABASE_URL) is not set; the hub cannot store data');
    return;
  }
  if (!e.adminSecret) {
    console.warn('[ai-security-monitor-hub] open mode (no AI_SECURITY_MONITOR_HUB_ADMIN_SECRET): everyone is admin — bind to 127.0.0.1 only');
  }
  try {
    const { ensureMigrated } = await import('./lib/db');
    await ensureMigrated();
    console.log('[ai-security-monitor-hub] database ready');
  } catch (err) {
    console.error('[ai-security-monitor-hub] migration failed; will retry on first request', err);
  }
}
