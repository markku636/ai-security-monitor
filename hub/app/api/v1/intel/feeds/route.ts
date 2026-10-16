// 情資來源登錄＋最近 7 天命中統計（來源資訊是公開的，公開檢視也可讀）。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { loadRegistry } from '@/lib/intel/registry';
import { feedHitStats } from '@/lib/queries/intel';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req, { allowViewer: true });
  if (id instanceof Response) return id;
  const stats = await feedHitStats(7);
  const items = loadRegistry().map((f) => {
    const s = stats.get(f.id);
    return { ...f, hits_7d: s ? { indicators: s.indicators, hosts: s.hosts, last_seen_at: s.lastSeenAt } : null };
  });
  return json({ items });
}
