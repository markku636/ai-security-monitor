// 威脅情資命中的彙總：哪些來源最常命中、命中了哪些指標（每筆都帶廠商、授權與來源網址）。
import { and, desc, eq, gte, isNull, sql } from 'drizzle-orm';
import { agents, intelHits } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

/** 依來源（feed）彙總最近 N 天的命中。 */
export async function topIntelFeeds(days = 7, limit = 10) {
  const since = new Date(Date.now() - days * 86_400_000);
  const rows = await getDb()
    .select({
      feedId: intelHits.feedId,
      feedName: sql<string>`max(${intelHits.feedName})`,
      vendor: sql<string>`max(${intelHits.vendor})`,
      license: sql<string>`max(${intelHits.license})`,
      sourceUrl: sql<string>`max(${intelHits.sourceUrl})`,
      maxConfidence: sql<number>`max(${intelHits.confidence})::int`,
      indicators: sql<number>`count(distinct ${intelHits.indicator})::int`,
      hosts: sql<number>`count(distinct ${intelHits.agentId})::int`,
      lastSeenAt: sql<Date>`max(${intelHits.seenAt})`,
    })
    .from(intelHits)
    .innerJoin(agents, and(eq(agents.id, intelHits.agentId), isNull(agents.deletedAt)))
    .where(gte(intelHits.seenAt, since))
    .groupBy(intelHits.feedId)
    .orderBy(desc(sql`count(distinct ${intelHits.indicator})`), desc(sql`max(${intelHits.confidence})`))
    .limit(limit);
  return rows.map((r) => ({ ...r, lastSeenAt: new Date(r.lastSeenAt) }));
}

/** 最近 N 天被命中的指標（IP／網域），附命中的來源清單。 */
export async function topIndicators(days = 7, limit = 10, agentId?: string) {
  const since = new Date(Date.now() - days * 86_400_000);
  const conds = [gte(intelHits.seenAt, since)];
  if (agentId) conds.push(eq(intelHits.agentId, agentId));
  const rows = await getDb()
    .select({
      indicator: intelHits.indicator,
      maxConfidence: sql<number>`max(${intelHits.confidence})::int`,
      hosts: sql<number>`count(distinct ${intelHits.agentId})::int`,
      sources: sql<{ feed_id: string; name: string; vendor: string; license: string; source_url: string; confidence: number }[]>`
        jsonb_agg(distinct jsonb_build_object(
          'feed_id', ${intelHits.feedId}, 'name', ${intelHits.feedName}, 'vendor', ${intelHits.vendor},
          'license', ${intelHits.license}, 'source_url', ${intelHits.sourceUrl}, 'confidence', ${intelHits.confidence}))`,
      lastSeenAt: sql<Date>`max(${intelHits.seenAt})`,
    })
    .from(intelHits)
    .innerJoin(agents, and(eq(agents.id, intelHits.agentId), isNull(agents.deletedAt)))
    .where(and(...conds))
    .groupBy(intelHits.indicator)
    .orderBy(desc(sql`max(${intelHits.confidence})`), desc(sql`max(${intelHits.seenAt})`))
    .limit(limit);
  return rows.map((r) => ({ ...r, lastSeenAt: new Date(r.lastSeenAt), sources: r.sources ?? [] }));
}
