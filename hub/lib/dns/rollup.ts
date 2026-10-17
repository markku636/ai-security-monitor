// DNS 每小時彙總＋保留期限：重算「有新紀錄進來的那幾個小時」（冪等，重跑結果一樣），
// 再刪掉超過保留天數的原始紀錄、彙總與太久沒出現的網域。跟流量彙總同一支排程（lib/metrics/rollup.ts），用自己的 advisory lock。
import { eq, gt, lt, sql } from 'drizzle-orm';
import { dnsDomains, dnsQueries, dnsQueriesHourly, dnsResolverQueries, settings } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';

const WATERMARK = 'dns.rollup_watermark';
/** 交易可能比 received_at 晚提交：往回多看一點。 */
const OVERLAP_MS = 5 * 60_000;
const HOUR = 3_600_000;

export interface DnsRollupResult {
  skipped: boolean;
  hours: number;
  deletedRaw: number;
  deletedHourly: number;
}

function rowsOf<T>(r: unknown): T[] {
  return (r as { rows?: T[] }).rows ?? (r as T[]) ?? [];
}

/** 跑一次彙總與清理。另一個行程正在跑就直接回 `skipped`。 */
export async function rollupDns(db: DB, now = new Date()): Promise<DnsRollupResult> {
  return db.transaction(async (tx) => {
    const t = tx as unknown as DB;
    const lock = rowsOf<{ ok: boolean }>(await t.execute(sql`select pg_try_advisory_xact_lock(hashtext('asa_hub.dns_rollup')) as ok`));
    if (!lock[0]?.ok) return { skipped: true, hours: 0, deletedRaw: 0, deletedHourly: 0 };
    const e = env();
    const [wm] = await t.select().from(settings).where(eq(settings.key, WATERMARK)).limit(1);
    const wmAt = typeof wm?.value === 'string' ? Date.parse(wm.value) : NaN;
    const since = new Date((Number.isFinite(wmAt) ? wmAt : 0) - OVERLAP_MS);
    const touched = await t
      .selectDistinct({ agentId: dnsQueries.agentId, hour: sql<string>`date_trunc('hour', ${dnsQueries.ts})`.as('hour') })
      .from(dnsQueries)
      .where(gt(dnsQueries.receivedAt, since));
    let hours = 0;
    for (const r of touched) {
      const from = new Date(Math.floor(new Date(r.hour).getTime() / HOUR) * HOUR);
      const to = new Date(from.getTime() + HOUR);
      await t.execute(sql`
        insert into dns_queries_hourly (agent_id, hour, registrable, queries, nxdomain, names, processes, updated_at)
        select agent_id, ${from.toISOString()}::timestamptz, registrable,
               sum(count)::int,
               coalesce(sum(count) filter (where rcode = 'NXDOMAIN'), 0)::int,
               count(distinct name)::int,
               coalesce(jsonb_agg(distinct process) filter (where process <> ''), '[]'::jsonb),
               now()
        from dns_queries
        where agent_id = ${r.agentId} and ts >= ${from.toISOString()}::timestamptz and ts < ${to.toISOString()}::timestamptz
        group by agent_id, registrable
        on conflict (agent_id, hour, registrable) do update set
          queries = excluded.queries, nxdomain = excluded.nxdomain, names = excluded.names,
          processes = excluded.processes, updated_at = excluded.updated_at`);
      hours++;
    }
    const rawCut = new Date(now.getTime() - e.dnsRawDays * 86_400_000);
    const hourlyCut = new Date(now.getTime() - e.dnsHourlyDays * 86_400_000);
    const delRaw = await t.delete(dnsQueries).where(lt(dnsQueries.ts, rawCut)).returning({ id: dnsQueries.id });
    const delHourly = await t.delete(dnsQueriesHourly).where(lt(dnsQueriesHourly.hour, hourlyCut)).returning({ a: dnsQueriesHourly.agentId });
    await t.delete(dnsDomains).where(lt(dnsDomains.lastSeenAt, hourlyCut));
    await t.delete(dnsResolverQueries).where(lt(dnsResolverQueries.ts, rawCut));
    await t
      .insert(settings)
      .values({ key: WATERMARK, value: now.toISOString(), updatedBy: 'dns-rollup' })
      .onConflictDoUpdate({ target: settings.key, set: { value: now.toISOString(), updatedAt: now } });
    return { skipped: false, hours, deletedRaw: delRaw.length, deletedHourly: delHourly.length };
  });
}
