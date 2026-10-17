// 伺服器啟動時（Node runtime）先跑 migration；資料庫暫時連不上不擋啟動，/api/health 會回 503。
// 另外裝 TCP 來源位址標頭（自動核准網段用）並啟動區網 mDNS 廣播。實作在 lib/instrumentation-node.ts。
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { registerNode } = await import('./lib/instrumentation-node');
    await registerNode();
  }
}
