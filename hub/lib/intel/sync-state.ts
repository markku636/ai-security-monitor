// 「叫所有主機立即更新情資」的時間戳（settings 表）；agent 心跳回報的最後檢查時間比它舊，就在回應裡帶 refresh_feeds。
import { eq } from 'drizzle-orm';
import { settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';

const KEY = 'feeds.refresh_requested_at';
/** 超過這麼久還沒更新的主機就不再催（多半離線或版本太舊）。 */
const MAX_AGE_MS = 24 * 3_600_000;

export async function refreshRequestedAt(db: DB): Promise<Date | null> {
  const [row] = await db.select().from(settings).where(eq(settings.key, KEY)).limit(1);
  const v = typeof row?.value === 'string' ? Date.parse(row.value) : NaN;
  return Number.isFinite(v) ? new Date(v) : null;
}

export async function requestRefresh(db: DB, by: string, now = new Date()): Promise<void> {
  await db
    .insert(settings)
    .values({ key: KEY, value: now.toISOString(), updatedBy: by })
    .onConflictDoUpdate({ target: settings.key, set: { value: now.toISOString(), updatedBy: by, updatedAt: now } });
}

/** agent 該不該更新：有人按過「叫所有主機更新」、還在 24 小時內、且這台的最後檢查比那時舊。 */
export function shouldRefresh(requested: Date | null, agentCheckedAt: Date | null, now = Date.now()): boolean {
  if (!requested || now - requested.getTime() > MAX_AGE_MS) return false;
  return !agentCheckedAt || agentCheckedAt < requested;
}
