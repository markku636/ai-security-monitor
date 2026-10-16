// 車隊流量概況（由連線快照與長期目的地彙總推算，不需要抓封包）。
import { and, desc, eq, gte, isNull, sql, type SQL } from 'drizzle-orm';
import { agents, connections, destinations } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

/** 最常連的目的地（依出現次數），可只看可疑／危險。 */
export async function topDestinations(o: { days?: number; agentId?: string; risky?: boolean; limit?: number } = {}) {
  const conds: SQL[] = [isNull(agents.deletedAt), gte(destinations.lastSeenAt, new Date(Date.now() - (o.days ?? 7) * 86_400_000))];
  if (o.agentId) conds.push(eq(destinations.agentId, o.agentId));
  if (o.risky) conds.push(sql`${destinations.worstVerdict} in ('dangerous', 'suspicious')`);
  return getDb()
    .select({
      agentId: destinations.agentId,
      hostname: agents.hostname,
      remoteIp: destinations.remoteIp,
      remotePort: destinations.remotePort,
      direction: destinations.direction,
      worstVerdict: destinations.worstVerdict,
      processName: destinations.processName,
      country: destinations.country,
      asn: destinations.asn,
      org: destinations.org,
      firstSeenAt: destinations.firstSeenAt,
      lastSeenAt: destinations.lastSeenAt,
      seenCount: destinations.seenCount,
    })
    .from(destinations)
    .innerJoin(agents, eq(agents.id, destinations.agentId))
    .where(and(...conds))
    .orderBy(desc(destinations.seenCount), desc(destinations.lastSeenAt))
    .limit(Math.min(o.limit ?? 50, 300));
}

/** 最近 N 小時第一次出現的目的地。 */
export async function newDestinations(hours = 24, limit = 50, agentId?: string) {
  const conds: SQL[] = [isNull(agents.deletedAt), gte(destinations.firstSeenAt, new Date(Date.now() - hours * 3_600_000))];
  if (agentId) conds.push(eq(destinations.agentId, agentId));
  return getDb()
    .select({
      agentId: destinations.agentId,
      hostname: agents.hostname,
      remoteIp: destinations.remoteIp,
      remotePort: destinations.remotePort,
      direction: destinations.direction,
      worstVerdict: destinations.worstVerdict,
      processName: destinations.processName,
      country: destinations.country,
      org: destinations.org,
      firstSeenAt: destinations.firstSeenAt,
    })
    .from(destinations)
    .innerJoin(agents, eq(agents.id, destinations.agentId))
    .where(and(...conds))
    .orderBy(desc(destinations.firstSeenAt))
    .limit(limit);
}

/** 依行程彙總目前連線（車隊或單一主機）。 */
export async function processActivity(agentId?: string, limit = 20) {
  const conds: SQL[] = [isNull(agents.deletedAt), sql`${connections.direction} in ('outbound', 'inbound')`];
  if (agentId) conds.push(eq(connections.agentId, agentId));
  const rows = await getDb()
    .select({
      process: sql<string>`coalesce(${connections.processName}, '?')`,
      conns: sql<number>`count(*)::int`,
      remotes: sql<number>`count(distinct ${connections.remoteIp})::int`,
      hosts: sql<number>`count(distinct ${connections.agentId})::int`,
      risky: sql<number>`count(*) filter (where ${connections.verdict} in ('dangerous', 'suspicious'))::int`,
    })
    .from(connections)
    .innerJoin(agents, eq(agents.id, connections.agentId))
    .where(and(...conds))
    .groupBy(sql`coalesce(${connections.processName}, '?')`)
    .orderBy(desc(sql`count(*)`))
    .limit(limit);
  return rows;
}
