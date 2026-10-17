// DNS 查詢紀錄的查詢：統計、熱門網域、新出現的網域、最近查詢、各主機蒐集狀態、單一網域明細。
// 期間統計用每小時彙總（快、可看 90 天）；明細與搜尋用原始紀錄（預設保留 7 天）。
import { and, desc, eq, gte, ilike, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import { agentSummaries, agents, dnsDomains, dnsQueries, dnsQueriesHourly, findings } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { likePattern } from './connections';

const HOUR = 3_600_000;

/** 合法的網域查詢字串（給 /domain/<name> 用）：小寫字母、數字、`-`、`_`、`.`，至少兩段。 */
export function normalizeDomain(raw: string): string | null {
  const d = decodeURIComponent(raw).trim().toLowerCase().replace(/\.$/, '');
  if (d.length < 3 || d.length > 253 || !d.includes('.')) return null;
  return /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(d) ? d : null;
}

function sinceDays(days: number, now = Date.now()): Date {
  return new Date(Math.floor((now - days * 86_400_000) / HOUR) * HOUR);
}

export interface DnsStats {
  queries: number;
  nxdomain: number;
  domains: number;
  hosts: number;
}

/** 期間內的查詢總數、NXDOMAIN、不同網域、有回報的主機數。 */
export async function dnsStats(days: number, agentId?: string): Promise<DnsStats> {
  const conds: SQL[] = [gte(dnsQueriesHourly.hour, sinceDays(days))];
  if (agentId) conds.push(eq(dnsQueriesHourly.agentId, agentId));
  const [r] = await getDb()
    .select({
      queries: sql<number>`coalesce(sum(${dnsQueriesHourly.queries}), 0)::int`,
      nxdomain: sql<number>`coalesce(sum(${dnsQueriesHourly.nxdomain}), 0)::int`,
      domains: sql<number>`count(distinct ${dnsQueriesHourly.registrable})::int`,
      hosts: sql<number>`count(distinct ${dnsQueriesHourly.agentId})::int`,
    })
    .from(dnsQueriesHourly)
    .where(and(...conds));
  return { queries: Number(r?.queries ?? 0), nxdomain: Number(r?.nxdomain ?? 0), domains: Number(r?.domains ?? 0), hosts: Number(r?.hosts ?? 0) };
}

export interface TopDomain {
  registrable: string;
  queries: number;
  nxdomain: number;
  hosts: number;
  names: number;
}

/** 期間內查詢最多的可註冊網域。 */
export async function topDomains(days: number, agentId?: string, limit = 20): Promise<TopDomain[]> {
  const conds: SQL[] = [gte(dnsQueriesHourly.hour, sinceDays(days))];
  if (agentId) conds.push(eq(dnsQueriesHourly.agentId, agentId));
  const q = sql<number>`sum(${dnsQueriesHourly.queries})::int`;
  const rows = await getDb()
    .select({
      registrable: dnsQueriesHourly.registrable,
      queries: q,
      nxdomain: sql<number>`sum(${dnsQueriesHourly.nxdomain})::int`,
      hosts: sql<number>`count(distinct ${dnsQueriesHourly.agentId})::int`,
      names: sql<number>`max(${dnsQueriesHourly.names})::int`,
    })
    .from(dnsQueriesHourly)
    .where(and(...conds))
    .groupBy(dnsQueriesHourly.registrable)
    .orderBy(desc(q))
    .limit(limit);
  return rows.map((r) => ({ ...r, queries: Number(r.queries), nxdomain: Number(r.nxdomain), hosts: Number(r.hosts), names: Number(r.names) }));
}

/** 全隊第一次出現在 `hours` 小時內的網域（新的、沒看過的網域值得看一眼）。 */
export async function newDomains(hours: number, limit = 30) {
  return getDb()
    .select({
      registrable: dnsDomains.registrable,
      firstSeenAt: dnsDomains.firstSeenAt,
      lastSeenAt: dnsDomains.lastSeenAt,
      agentId: dnsDomains.firstAgentId,
      hostname: agents.hostname,
      process: dnsDomains.firstProcess,
    })
    .from(dnsDomains)
    .leftJoin(agents, eq(agents.id, dnsDomains.firstAgentId))
    .where(gte(dnsDomains.firstSeenAt, new Date(Date.now() - hours * HOUR)))
    .orderBy(desc(dnsDomains.firstSeenAt))
    .limit(limit);
}

export interface RecentFilter {
  agentId?: string;
  q?: string;
  /** 只看 NXDOMAIN。 */
  nx?: boolean;
  limit: number;
}

/** 最近的查詢（原始紀錄，新到舊）。`q` 比對網域名稱或程式。 */
export async function recentQueries(f: RecentFilter) {
  const conds: SQL[] = [isNull(agents.deletedAt)];
  if (f.agentId) conds.push(eq(dnsQueries.agentId, f.agentId));
  if (f.q) {
    const p = likePattern(f.q.toLowerCase());
    conds.push(or(ilike(dnsQueries.name, p), ilike(dnsQueries.process, p)) as SQL);
  }
  if (f.nx) conds.push(eq(dnsQueries.rcode, 'NXDOMAIN'));
  return getDb()
    .select({
      ts: dnsQueries.ts,
      agentId: dnsQueries.agentId,
      hostname: agents.hostname,
      name: dnsQueries.name,
      registrable: dnsQueries.registrable,
      qtype: dnsQueries.qtype,
      rcode: dnsQueries.rcode,
      process: dnsQueries.process,
      count: dnsQueries.count,
      answers: dnsQueries.answers,
      source: dnsQueries.source,
    })
    .from(dnsQueries)
    .innerJoin(agents, eq(agents.id, dnsQueries.agentId))
    .where(and(...conds))
    .orderBy(desc(dnsQueries.ts))
    .limit(f.limit);
}

export interface CollectorRow {
  agentId: string;
  hostname: string;
  at: Date | null;
  source: string | null;
  running: boolean;
  hasProcess: boolean;
  lastEventAt: string | null;
  queries: number | null;
  notes: string[];
}

/** 各主機 DNS 監看的狀態（掃描報告帶的 `summaries.dns`）。 */
export async function collectorStatus(agentId?: string): Promise<CollectorRow[]> {
  const conds: SQL[] = [isNull(agents.deletedAt)];
  if (agentId) conds.push(eq(agents.id, agentId));
  const rows = await getDb()
    .select({ agentId: agents.id, hostname: agents.hostname, at: agentSummaries.at, summary: agentSummaries.summary })
    .from(agents)
    .leftJoin(agentSummaries, and(eq(agentSummaries.agentId, agents.id), eq(agentSummaries.kind, 'dns')))
    .where(and(...conds))
    .orderBy(agents.hostname);
  return rows.map((r) => {
    const s = (r.summary ?? {}) as Record<string, unknown>;
    const c = (s.collector ?? {}) as Record<string, unknown>;
    return {
      agentId: r.agentId,
      hostname: r.hostname,
      at: r.at,
      source: typeof c.source === 'string' ? c.source : null,
      running: c.running === true,
      hasProcess: c.has_process === true,
      lastEventAt: typeof c.last_event_at === 'string' ? c.last_event_at : null,
      queries: typeof s.queries === 'number' ? s.queries : null,
      notes: Array.isArray(c.notes) ? (c.notes as unknown[]).filter((x): x is string => typeof x === 'string') : [],
    };
  });
}

/** 未處理的 DNS 問題數（側欄、統計卡）。 */
export async function openDnsFindings(agentId?: string): Promise<number> {
  const conds: SQL[] = [eq(findings.scanner, 'dns'), inArray(findings.status, ['open', 'acked'])];
  if (agentId) conds.push(eq(findings.agentId, agentId));
  const [r] = await getDb().select({ n: sql<number>`count(*)::int` }).from(findings).where(and(...conds));
  return Number(r?.n ?? 0);
}

/** 單一網域（或可註冊網域）的明細：哪些主機／程式查過、解析到哪些 IP、結果、每小時次數、相關問題。 */
export async function domainDetail(name: string) {
  const db = getDb();
  const asRegistrable = sql`${dnsQueries.registrable} = ${name}`;
  const exact = eq(dnsQueries.name, name);
  const match = or(asRegistrable, exact) as SQL;
  const [byHost, rcodes, names, answers, domainRow, hourly, related] = await Promise.all([
    db
      .select({
        agentId: dnsQueries.agentId,
        hostname: agents.hostname,
        process: dnsQueries.process,
        queries: sql<number>`sum(${dnsQueries.count})::int`,
        first: sql<Date>`min(${dnsQueries.ts})`,
        last: sql<Date>`max(${dnsQueries.ts})`,
      })
      .from(dnsQueries)
      .innerJoin(agents, eq(agents.id, dnsQueries.agentId))
      .where(match)
      .groupBy(dnsQueries.agentId, agents.hostname, dnsQueries.process)
      .orderBy(desc(sql`sum(${dnsQueries.count})`))
      .limit(50),
    db
      .select({ rcode: dnsQueries.rcode, queries: sql<number>`sum(${dnsQueries.count})::int` })
      .from(dnsQueries)
      .where(match)
      .groupBy(dnsQueries.rcode),
    db
      .select({ name: dnsQueries.name, queries: sql<number>`sum(${dnsQueries.count})::int` })
      .from(dnsQueries)
      .where(match)
      .groupBy(dnsQueries.name)
      .orderBy(desc(sql`sum(${dnsQueries.count})`))
      .limit(30),
    db
      .select({ ip: sql<string>`jsonb_array_elements_text(${dnsQueries.answers})` })
      .from(dnsQueries)
      .where(match)
      .limit(2000),
    db.select().from(dnsDomains).where(eq(dnsDomains.registrable, name)).limit(1),
    db
      .select({ hour: dnsQueriesHourly.hour, queries: sql<number>`sum(${dnsQueriesHourly.queries})::int` })
      .from(dnsQueriesHourly)
      .where(and(eq(dnsQueriesHourly.registrable, name), gte(dnsQueriesHourly.hour, sinceDays(7))))
      .groupBy(dnsQueriesHourly.hour)
      .orderBy(dnsQueriesHourly.hour),
    db
      .select({
        agentId: findings.agentId,
        findingId: findings.findingId,
        hostname: agents.hostname,
        rule: findings.rule,
        severity: findings.severity,
        title: findings.title,
        status: findings.status,
        lastSeenAt: findings.lastSeenAt,
      })
      .from(findings)
      .innerJoin(agents, eq(agents.id, findings.agentId))
      .where(and(eq(findings.scanner, 'dns'), eq(findings.indicator, name)))
      .orderBy(desc(findings.lastSeenAt))
      .limit(20),
  ]);
  const ipCount = new Map<string, number>();
  for (const a of answers) ipCount.set(a.ip, (ipCount.get(a.ip) ?? 0) + 1);
  return {
    byHost: byHost.map((r) => ({ ...r, queries: Number(r.queries) })),
    rcodes: rcodes.map((r) => ({ ...r, queries: Number(r.queries) })),
    names: names.map((r) => ({ ...r, queries: Number(r.queries) })),
    ips: [...ipCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30).map(([ip]) => ip),
    domain: domainRow[0] ?? null,
    hourly: hourly.map((r) => ({ hour: r.hour, queries: Number(r.queries) })),
    related,
  };
}

/** AI／MCP 用：精簡的 DNS 摘要（期間統計、熱門網域、新網域、未處理的 DNS 問題）。 */
export async function dnsDigest(days: number, agentId?: string) {
  const [stats, top, fresh, open] = await Promise.all([
    dnsStats(days, agentId),
    topDomains(days, agentId, 15),
    newDomains(24, 20),
    getDb()
      .select({ hostname: agents.hostname, rule: findings.rule, severity: findings.severity, title: findings.title, indicator: findings.indicator, lastSeenAt: findings.lastSeenAt })
      .from(findings)
      .innerJoin(agents, eq(agents.id, findings.agentId))
      .where(and(eq(findings.scanner, 'dns'), inArray(findings.status, ['open', 'acked']), ...(agentId ? [eq(findings.agentId, agentId)] : [])))
      .orderBy(desc(findings.lastSeenAt))
      .limit(30),
  ]);
  return { days, stats, top_domains: top, new_domains_24h: fresh, open_findings: open };
}
