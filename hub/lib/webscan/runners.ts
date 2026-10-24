// 網站掃描端（webscan runner）的身分與在線狀態：比照防護 DNS（dns_servers），online 在讀取時依最後聯絡時間算。
import { desc, eq } from 'drizzle-orm';
import { apiTokens, webscanRunners } from '@/drizzle/schema';
import { hasScope, type Identity } from '@/lib/auth/access';
import type { DB } from '@/lib/db';
import type { ClaimRequestT } from './contract';

/** 超過這麼久沒聯絡就算離線（閒置時每 15 秒認領一次、掃描中每個工作各自送心跳）。 */
export const RUNNER_STALE_MS = 3 * 60_000;

export interface RunnerWho {
  id: string;
  name: string;
}

/** 呼叫者是哪一台掃描端：webscan 權杖（網頁建立的，或 compose 的 AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN）。其他身分 → null。 */
export async function webscanRunnerOf(id: Identity, db: DB): Promise<RunnerWho | null> {
  if (!hasScope(id, 'webscan')) return null;
  if (id.tokenId === 'env-webscan') return { id: 'env', name: 'compose' };
  const t = (await db.select({ name: apiTokens.name }).from(apiTokens).where(eq(apiTokens.id, id.tokenId ?? '')).limit(1))[0];
  return { id: `token:${id.tokenId}`, name: t?.name ?? `token ${id.tokenId}` };
}

/** 認領時順便更新掃描端的版本、能力與自己的位址（內容不信任：截斷、限制數量）。 */
export async function touchRunner(db: DB, who: RunnerWho, c: ClaimRequestT | null, sourceIp: string, now = new Date()): Promise<void> {
  const patch = c
    ? {
        version: c.version.slice(0, 40),
        hostname: c.hostname.slice(0, 255),
        capabilities: c.capabilities.slice(0, 32).map((x) => ({
          scanner: x.scanner.slice(0, 40),
          version: x.version.slice(0, 80),
          ...(x.templates ? { templates: x.templates.slice(0, 80) } : {}),
        })),
        selfIps: c.self_ips.slice(0, 64),
        sourceIp,
      }
    : {};
  await db
    .insert(webscanRunners)
    .values({ id: who.id, name: who.name, firstSeenAt: now, lastSeenAt: now, ...patch })
    .onConflictDoUpdate({ target: webscanRunners.id, set: { name: who.name, lastSeenAt: now, ...patch } });
}

export async function listRunners(db: DB, now = new Date()) {
  const rows = await db.select().from(webscanRunners).orderBy(desc(webscanRunners.lastSeenAt)).limit(50);
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    version: r.version,
    hostname: r.hostname,
    sourceIp: r.sourceIp,
    capabilities: r.capabilities,
    firstSeenAt: r.firstSeenAt.toISOString(),
    lastSeenAt: r.lastSeenAt.toISOString(),
    online: now.getTime() - r.lastSeenAt.getTime() < RUNNER_STALE_MS,
  }));
}
export type RunnerView = Awaited<ReturnType<typeof listRunners>>[number];
