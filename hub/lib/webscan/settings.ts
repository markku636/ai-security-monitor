// 網站掃描的設定（settings 表 webscan.settings）：內網網段白名單、預設速率與逾時、停用的掃描器、第三方來源開關。
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { normalizeCidrList } from '@/lib/enroll/cidr';
import { WEBSCAN_SCANNERS } from './scanners';

export const WEBSCAN_SETTINGS_KEY = 'webscan.settings';

export const WebscanSettings = z.object({
  /** 允許掃描的內網網段（解析到私有位址的目標只有落在這裡面才放行）。 */
  internal_cidrs: z.array(z.string().max(64)).max(64).default([]),
  /** 每秒最多幾個請求（每個掃描器各自）。 */
  rate_per_sec: z.number().int().min(1).max(50).default(10),
  concurrency: z.number().int().min(1).max(10).default(5),
  /** 一次掃描最長幾分鐘（逾時就停）。 */
  timeout_minutes: z.number().int().min(1).max(180).default(30),
  disabled_scanners: z.array(z.enum(WEBSCAN_SCANNERS)).max(WEBSCAN_SCANNERS.length).default([]),
  /** 會把網域送給第三方來源的工具（例如被動子網域列舉）；預設關。 */
  third_party: z.boolean().default(false),
});
export type WebscanSettingsT = z.infer<typeof WebscanSettings>;

export function defaultWebscanSettings(): WebscanSettingsT {
  return WebscanSettings.parse({});
}

export async function getWebscanSettings(db: DB): Promise<WebscanSettingsT> {
  const row = (await db.select().from(settings).where(eq(settings.key, WEBSCAN_SETTINGS_KEY)).limit(1))[0];
  const p = WebscanSettings.safeParse(row?.value ?? {});
  return p.success ? p.data : defaultWebscanSettings();
}

/** 只改有送的欄位；CIDR 正規化（單一 IP → /32），太寬（/8 以下）或格式錯回 `{ error }`。 */
export async function setWebscanSettings(
  db: DB,
  input: unknown,
  actor: string,
): Promise<{ before: WebscanSettingsT; after: WebscanSettingsT } | { error: string }> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'bad_request' };
  const before = await getWebscanSettings(db);
  const merged = WebscanSettings.safeParse({ ...before, ...(input as Record<string, unknown>) });
  if (!merged.success) return { error: `invalid:${merged.error.issues[0]?.path.join('.') ?? ''}` };
  const cidrs = normalizeCidrList(merged.data.internal_cidrs);
  if (!Array.isArray(cidrs)) return { error: `${cidrs.error}:${cidrs.value}` };
  const after = { ...merged.data, internal_cidrs: cidrs, disabled_scanners: [...new Set(merged.data.disabled_scanners)] };
  await db
    .insert(settings)
    .values({ key: WEBSCAN_SETTINGS_KEY, value: after, updatedBy: actor })
    .onConflictDoUpdate({ target: settings.key, set: { value: after, updatedBy: actor, updatedAt: new Date() } });
  return { before, after };
}
