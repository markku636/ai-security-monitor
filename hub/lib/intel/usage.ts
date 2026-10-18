// Hub 的情資使用情境：只限非商業用途的來源（授權 commercial_ok=false，例如 DShield、URLhaus、ThreatFox）只在「非商用」時鏡像給主機。
// 環境變數 AI_SECURITY_MONITOR_HUB_INTEL_USAGE（commercial／noncommercial）優先並鎖定網頁設定；沒設時看映像版本
// （ghcr 的 -commercial／-noncommercial 標籤帶 AI_SECURITY_MONITOR_HUB_IMAGE_INTEL_USAGE，一樣鎖定）；預設非商用。
import { eq } from 'drizzle-orm';
import { settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { readEnv } from '@/lib/env';

export type IntelUsage = 'commercial' | 'noncommercial';
const KEY = 'intel_usage';

export function isIntelUsage(v: unknown): v is IntelUsage {
  return v === 'commercial' || v === 'noncommercial';
}

export async function getIntelUsage(db: DB): Promise<{ usage: IntelUsage; source: 'env' | 'settings' | 'default' }> {
  const fromEnv = (readEnv('ASA_HUB_INTEL_USAGE').trim() || (process.env.AI_SECURITY_MONITOR_HUB_IMAGE_INTEL_USAGE ?? '').trim()).toLowerCase();
  if (isIntelUsage(fromEnv)) return { usage: fromEnv, source: 'env' };
  const row = (await db.select().from(settings).where(eq(settings.key, KEY)).limit(1))[0];
  if (isIntelUsage(row?.value)) return { usage: row.value, source: 'settings' };
  return { usage: 'noncommercial', source: 'default' };
}

/** 能不能鏡像只限非商業用途的來源（讀不到資料庫時當作不能）。 */
export async function allowNoncommercial(db: DB): Promise<boolean> {
  try {
    return (await getIntelUsage(db)).usage === 'noncommercial';
  } catch {
    return false;
  }
}

export async function setIntelUsage(db: DB, input: unknown, actor: string): Promise<{ before: IntelUsage; after: IntelUsage } | { error: 'bad_usage' | 'locked_by_env' }> {
  if (!isIntelUsage(input)) return { error: 'bad_usage' };
  const cur = await getIntelUsage(db);
  if (cur.source === 'env') return { error: 'locked_by_env' };
  await db
    .insert(settings)
    .values({ key: KEY, value: input, updatedBy: actor, updatedAt: new Date() })
    .onConflictDoUpdate({ target: settings.key, set: { value: input, updatedBy: actor, updatedAt: new Date() } });
  return { before: cur.usage, after: input };
}
