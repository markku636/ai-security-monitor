// 當機與資安事件的查詢（頁面、API、hub MCP 共用）。
import { and, desc, eq, gte, inArray, isNull, sql, type SQL } from 'drizzle-orm';
import { agentSummaries, agents, crashRecords, securityEvents } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

const since = (days: number) => new Date(Date.now() - days * 86_400_000);

export async function crashCounts(days = 30, agentId?: string) {
  const conds: SQL[] = [gte(crashRecords.time, since(days)), isNull(agents.deletedAt)];
  if (agentId) conds.push(eq(crashRecords.agentId, agentId));
  const rows = await getDb()
    .select({ kind: crashRecords.kind, n: sql<number>`count(*)::int`, hosts: sql<number>`count(distinct ${crashRecords.agentId})::int` })
    .from(crashRecords)
    .innerJoin(agents, eq(agents.id, crashRecords.agentId))
    .where(and(...conds))
    .groupBy(crashRecords.kind);
  return Object.fromEntries(rows.map((r) => [r.kind, { count: Number(r.n), hosts: Number(r.hosts) }])) as Record<string, { count: number; hosts: number }>;
}

export async function recentCrashes(o: { days?: number; agentId?: string; kinds?: string[]; limit?: number } = {}) {
  const conds: SQL[] = [gte(crashRecords.time, since(o.days ?? 30)), isNull(agents.deletedAt)];
  if (o.agentId) conds.push(eq(crashRecords.agentId, o.agentId));
  if (o.kinds?.length) conds.push(inArray(crashRecords.kind, o.kinds));
  return getDb()
    .select({
      id: crashRecords.id,
      agentId: crashRecords.agentId,
      hostname: agents.hostname,
      time: crashRecords.time,
      kind: crashRecords.kind,
      code: crashRecords.code,
      name: crashRecords.name,
      module: crashRecords.module,
      process: crashRecords.process,
      details: crashRecords.details,
    })
    .from(crashRecords)
    .innerJoin(agents, eq(agents.id, crashRecords.agentId))
    .where(and(...conds))
    .orderBy(desc(crashRecords.time))
    .limit(Math.min(o.limit ?? 100, 500));
}

/** 最常見的藍屏代碼（附名稱、次數、影響主機數、最近一次）。 */
export async function topBugchecks(days = 30, limit = 10, agentId?: string) {
  const rows = await getDb()
    .select({
      code: crashRecords.code,
      name: sql<string | null>`max(${crashRecords.name})`,
      count: sql<number>`count(*)::int`,
      hosts: sql<number>`count(distinct ${crashRecords.agentId})::int`,
      last: sql<Date>`max(${crashRecords.time})`,
    })
    .from(crashRecords)
    .innerJoin(agents, and(eq(agents.id, crashRecords.agentId), isNull(agents.deletedAt)))
    .where(and(eq(crashRecords.kind, 'bugcheck'), gte(crashRecords.time, since(days)), agentId ? eq(crashRecords.agentId, agentId) : undefined))
    .groupBy(crashRecords.code)
    .orderBy(desc(sql`count(*)`))
    .limit(limit);
  return rows.map((r) => ({ ...r, last: new Date(r.last) }));
}

const SEV_ORDER = sql`case ${securityEvents.severity} when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end`;

export async function securityHits(o: { days?: number; agentId?: string; rules?: string[]; minSeverity?: 'low' | 'medium' | 'high'; limit?: number } = {}) {
  const conds: SQL[] = [gte(securityEvents.lastAt, since(o.days ?? 30)), isNull(agents.deletedAt)];
  if (o.agentId) conds.push(eq(securityEvents.agentId, o.agentId));
  if (o.rules?.length) conds.push(inArray(securityEvents.rule, o.rules));
  if (o.minSeverity) {
    const allowed = { low: ['low', 'medium', 'high', 'critical'], medium: ['medium', 'high', 'critical'], high: ['high', 'critical'] }[o.minSeverity];
    conds.push(inArray(securityEvents.severity, allowed));
  }
  return getDb()
    .select({
      id: securityEvents.id,
      agentId: securityEvents.agentId,
      hostname: agents.hostname,
      rule: securityEvents.rule,
      severity: securityEvents.severity,
      count: securityEvents.count,
      firstAt: securityEvents.firstAt,
      lastAt: securityEvents.lastAt,
      sourceIp: securityEvents.sourceIp,
      userName: securityEvents.userName,
      detail: securityEvents.detail,
      intel: securityEvents.intel,
    })
    .from(securityEvents)
    .innerJoin(agents, eq(agents.id, securityEvents.agentId))
    .where(and(...conds))
    .orderBy(SEV_ORDER, desc(securityEvents.lastAt))
    .limit(Math.min(o.limit ?? 100, 500));
}

/** 暴力破解來源：跨主機彙總同一個來源 IP。 */
export async function bruteForceSources(days = 30, limit = 20, agentId?: string) {
  const rows = await getDb()
    .select({
      sourceIp: sql<string>`${securityEvents.sourceIp}`,
      attempts: sql<number>`sum(${securityEvents.count})::int`,
      hosts: sql<number>`count(distinct ${securityEvents.agentId})::int`,
      last: sql<Date>`max(${securityEvents.lastAt})`,
      intel: sql<unknown[][]>`jsonb_agg(${securityEvents.intel})`,
    })
    .from(securityEvents)
    .innerJoin(agents, and(eq(agents.id, securityEvents.agentId), isNull(agents.deletedAt)))
    .where(
      and(
        eq(securityEvents.rule, 'failed_logon_burst'),
        gte(securityEvents.lastAt, since(days)),
        sql`${securityEvents.sourceIp} is not null`,
        agentId ? eq(securityEvents.agentId, agentId) : undefined,
      ),
    )
    .groupBy(securityEvents.sourceIp)
    .orderBy(desc(sql`sum(${securityEvents.count})`))
    .limit(limit);
  return rows.map((r) => {
    const seen = new Set<string>();
    const intel = (r.intel ?? []).flat().filter((x): x is { feed_id: string; vendor: string; confidence: number; source_url: string } => {
      const k = (x as { feed_id?: string })?.feed_id;
      if (!k || seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    return { ...r, last: new Date(r.last), intel };
  });
}

export async function latestSummary(agentId: string, kind: 'events' | 'traffic' | 'vuln' | 'hardening') {
  const rows = await getDb()
    .select()
    .from(agentSummaries)
    .where(and(eq(agentSummaries.agentId, agentId), eq(agentSummaries.kind, kind)))
    .limit(1);
  return rows[0] ?? null;
}
