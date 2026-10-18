// 資安報告：依選定區間（可限定一台主機）彙整安全分數、問題（新增／處理／期末待處理）、威脅情資命中、
// 危險與可疑連線、DNS、資安事件、封鎖動作與 MITRE ATT&CK 技術。只讀資料庫、不送任何東西出去。
import { sql, type SQL } from 'drizzle-orm';
import { TECHNIQUES } from '@/lib/attack/catalog';
import { mapRule } from '@/lib/attack/mapping';
import type { DB } from '@/lib/db';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Sev = (typeof SEVERITIES)[number];
export type SevCounts = Record<Sev, number>;
/** 一份報告最長涵蓋幾天。 */
export const MAX_DAYS = 366;

export interface ReportParams {
  from: Date;
  /** 不含（區間是 [from, to)）。 */
  to: Date;
  agentId?: string | null;
}

export interface SecurityReport {
  generatedAt: string;
  from: string;
  to: string;
  days: number;
  agent: { id: string; hostname: string } | null;
  hosts: { total: number; reporting: number };
  score: {
    start: number | null;
    end: number | null;
    trend: { day: string; overall: number }[];
    lowest: { agentId: string; hostname: string; overall: number }[];
  };
  findings: {
    newBySev: SevCounts;
    resolvedBySev: SevCounts;
    openEndBySev: SevCounts;
    byScanner: { scanner: string; count: number }[];
    topRules: { rule: string; title: string; severity: Sev; count: number; hosts: number }[];
    topNew: { agentId: string; hostname: string; severity: Sev; title: string; rule: string; firstSeenAt: string }[];
  };
  intel: {
    hits: number;
    indicators: number;
    hosts: number;
    byFeed: { vendor: string; feed: string; hits: number }[];
    topIndicators: { indicator: string; hits: number; hosts: number }[];
  };
  connections: {
    dangerous: number;
    suspicious: number;
    topIps: { ip: string; verdict: string; seen: number; hosts: number; country: string | null; org: string | null; process: string | null; note: string | null }[];
  };
  dns: { queries: number; nxdomain: number; domains: number; alerts: number; blocked: number; topBlocked: { domain: string; count: number }[] };
  events: { total: number; sources: number; byRule: { rule: string; count: number; hosts: number }[] };
  actions: { total: number; byKind: { kind: string; status: string; count: number }[]; autoBlocks: number };
  mitre: { id: string; name: string; nameEn: string; count: number }[];
}

type Row = Record<string, unknown>;
function rowsOf(r: unknown): Row[] {
  if (Array.isArray(r)) return r as Row[];
  return ((r as { rows?: Row[] })?.rows ?? []) as Row[];
}
const num = (v: unknown): number => (v == null ? 0 : Number(v));
const optNum = (v: unknown): number | null => (v == null ? null : Math.round(Number(v) * 10) / 10);
const str = (v: unknown): string => (v == null ? '' : String(v));
const iso = (v: unknown): string => (v instanceof Date ? v.toISOString() : new Date(String(v)).toISOString());

function sevCounts(rows: Row[]): SevCounts {
  const out: SevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of rows) {
    const s = str(r.severity) as Sev;
    if (s in out) out[s] += num(r.n);
  }
  return out;
}

const SEV_RANK = sql`case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end`;

/** 起訖（YYYY-MM-DD，含迄日）→ [from, to)；不合法或超過上限回 null。 */
export function parsePeriod(fromStr: string | undefined, toStr: string | undefined, now = new Date()): { from: Date; to: Date } | null {
  const day = (s: string) => (/^\d{4}-\d{2}-\d{2}$/.test(s) ? new Date(`${s}T00:00:00Z`) : null);
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const to = toStr ? day(toStr) : today;
  const from = fromStr ? day(fromStr) : to ? new Date(to.getTime() - 6 * 86_400_000) : null;
  if (!from || !to || Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from > to) return null;
  const end = new Date(to.getTime() + 86_400_000);
  if ((end.getTime() - from.getTime()) / 86_400_000 > MAX_DAYS) return null;
  return { from, to: end };
}

export async function buildReport(db: DB, p: ReportParams, now = new Date()): Promise<SecurityReport> {
  const from = p.from.toISOString();
  const to = p.to.toISOString();
  const agent = p.agentId ?? null;
  const live = sql`join agents a on a.id = x.agent_id and a.deleted_at is null`;
  const only = (col: SQL = sql`x.agent_id`) => (agent ? sql`and ${col} = ${agent}` : sql``);
  const q = async (s: SQL) => rowsOf(await db.execute(s));

  const [agentRow] = agent ? await q(sql`select id, hostname from agents where id = ${agent}`) : [];

  // 主機
  const [hostsRow] = await q(sql`
    select (select count(*) from agents where deleted_at is null ${agent ? sql`and id = ${agent}` : sql``})::int as total,
           (select count(distinct x.agent_id) from reports x ${live}
              where x.finished_at >= ${from}::timestamptz and x.finished_at < ${to}::timestamptz ${only()})::int as reporting`);

  // 分數：期末＝區間結束前最後一份報告；期初＝區間開始前最後一份（沒有就用區間內第一份）
  const avgAt = async (cond: SQL, order: SQL) => {
    const [r] = await q(sql`
      with e as (
        select distinct on (x.agent_id) x.agent_id, (x.score->>'overall')::float8 as o
        from reports x ${live}
        where ${cond} ${only()}
        order by x.agent_id, ${order})
      select avg(o) as o from e`);
    return optNum(r?.o);
  };
  const end = await avgAt(sql`x.finished_at < ${to}::timestamptz`, sql`x.finished_at desc`);
  const start =
    (await avgAt(sql`x.finished_at < ${from}::timestamptz`, sql`x.finished_at desc`)) ??
    (await avgAt(sql`x.finished_at >= ${from}::timestamptz and x.finished_at < ${to}::timestamptz`, sql`x.finished_at asc`));
  const trend = await q(sql`
    select date_trunc('day', x.finished_at) as d, avg((x.score->>'overall')::float8) as o
    from reports x ${live}
    where x.finished_at >= ${from}::timestamptz and x.finished_at < ${to}::timestamptz ${only()}
    group by 1 order by 1`);
  const lowest = await q(sql`
    with e as (
      select distinct on (x.agent_id) x.agent_id, (x.score->>'overall')::float8 as o
      from reports x ${live}
      where x.finished_at < ${to}::timestamptz ${only()}
      order by x.agent_id, x.finished_at desc)
    select e.agent_id, a.hostname, e.o from e join agents a on a.id = e.agent_id order by e.o asc limit 5`);

  // 問題
  const inRange = (col: SQL) => sql`${col} >= ${from}::timestamptz and ${col} < ${to}::timestamptz`;
  const fNew = sql`from findings x ${live} where ${inRange(sql`x.first_seen_at`)} ${only()}`;
  const newBySev = sevCounts(await q(sql`select x.severity, count(*)::int as n ${fNew} group by 1`));
  const resolvedBySev = sevCounts(
    await q(sql`select x.severity, count(*)::int as n from findings x ${live} where ${inRange(sql`x.resolved_at`)} ${only()} group by 1`),
  );
  const openEndBySev = sevCounts(
    await q(sql`
      select x.severity, count(*)::int as n from findings x ${live}
      where x.first_seen_at < ${to}::timestamptz and (x.resolved_at is null or x.resolved_at >= ${to}::timestamptz)
        and x.status <> 'resolved' ${only()}
      group by 1`),
  );
  const byScanner = await q(sql`select x.scanner, count(*)::int as n ${fNew} group by 1 order by 2 desc`);
  const topRules = await q(sql`
    select x.rule, max(x.title) as title, min(${SEV_RANK}) as r, count(*)::int as n, count(distinct x.agent_id)::int as hosts
    ${fNew} group by x.rule order by min(${SEV_RANK}), count(*) desc limit 12`);
  const topNew = await q(sql`
    select x.agent_id, a.hostname, x.severity, x.title, x.rule, x.first_seen_at
    ${fNew} and x.severity in ('critical', 'high')
    order by ${SEV_RANK}, x.first_seen_at desc limit 15`);

  // 威脅情資命中
  const ih = sql`from intel_hits x ${live} where ${inRange(sql`x.seen_at`)} ${only()}`;
  const [intelTot] = await q(sql`select count(*)::int as n, count(distinct x.indicator)::int as ind, count(distinct x.agent_id)::int as hosts ${ih}`);
  const byFeed = await q(sql`select x.vendor, x.feed_name, count(*)::int as n ${ih} group by 1, 2 order by 3 desc limit 10`);
  const topInd = await q(sql`select x.indicator, count(*)::int as n, count(distinct x.agent_id)::int as hosts ${ih} group by 1 order by 2 desc limit 10`);

  // 危險與可疑連線（區間內有被判定為危險／可疑的遠端 IP）
  const dst = sql`from destinations x ${live} where ${inRange(sql`x.last_risky_at`)} and x.worst_verdict in ('dangerous', 'suspicious') ${only()}`;
  const [connTot] = await q(sql`
    select count(distinct x.remote_ip) filter (where x.worst_verdict = 'dangerous')::int as dangerous,
           count(distinct x.remote_ip) filter (where x.worst_verdict = 'suspicious')::int as suspicious ${dst}`);
  const topIps = await q(sql`
    select x.remote_ip, min(case x.worst_verdict when 'dangerous' then 0 else 1 end) as v,
           sum(x.seen_count)::int as seen, count(distinct x.agent_id)::int as hosts,
           max(x.country) as country, max(x.org) as org, max(x.process_name) as process,
           (select n.note from ip_notes n where n.ip = x.remote_ip) as note
    ${dst} group by x.remote_ip order by 2, 3 desc limit 10`);

  // DNS（總量用每小時彙總，長區間也算得到）
  const [dnsTot] = await q(sql`
    select coalesce(sum(x.queries), 0)::bigint as queries, coalesce(sum(x.nxdomain), 0)::bigint as nx, count(distinct x.registrable)::int as domains
    from dns_queries_hourly x ${live} where ${inRange(sql`x.hour`)} ${only()}`);
  const [dnsBlocked] = await q(sql`
    select coalesce(sum(x.count), 0)::bigint as n from dns_resolver_queries x
    where x.rcode = 'BLOCKED' and ${inRange(sql`x.ts`)} ${agent ? sql`and x.agent_id = ${agent}` : sql``}`);
  const topBlocked = await q(sql`
    select x.registrable, sum(x.count)::bigint as n from dns_resolver_queries x
    where x.rcode = 'BLOCKED' and ${inRange(sql`x.ts`)} ${agent ? sql`and x.agent_id = ${agent}` : sql``}
    group by 1 order by 2 desc limit 10`);

  // 資安事件
  const ev = sql`from security_events x ${live} where x.last_at >= ${from}::timestamptz and x.first_at < ${to}::timestamptz ${only()}`;
  const [evTot] = await q(sql`select coalesce(sum(x.count), 0)::bigint as n, count(distinct x.source_ip)::int as sources ${ev}`);
  const evRules = await q(sql`select x.rule, sum(x.count)::bigint as n, count(distinct x.agent_id)::int as hosts ${ev} group by 1 order by 2 desc limit 10`);

  // 遠端動作與自動封鎖
  const acts = await q(sql`
    select x.kind, x.status, count(*)::int as n from actions x ${live}
    where ${inRange(sql`x.created_at`)} ${only()} group by 1, 2 order by 3 desc`);
  const [autoBlocks] = await q(sql`
    select count(*)::int as n from response_blocks x ${live} where ${inRange(sql`x.blocked_at`)} ${only()}`);

  // MITRE ATT&CK：區間內新問題的規則對應到的技術
  const ruleCounts = await q(sql`select x.rule, count(*)::int as n ${fNew} group by 1`);
  const tech = new Map<string, number>();
  for (const r of ruleCounts) for (const id of mapRule(str(r.rule)).mitre) tech.set(id, (tech.get(id) ?? 0) + num(r.n));
  const mitre = [...tech]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([id, count]) => ({ id, count, name: TECHNIQUES[id]?.zh ?? id, nameEn: TECHNIQUES[id]?.en ?? id }));

  return {
    generatedAt: now.toISOString(),
    from,
    to,
    days: Math.round((p.to.getTime() - p.from.getTime()) / 86_400_000),
    agent: agentRow ? { id: str(agentRow.id), hostname: str(agentRow.hostname) } : null,
    hosts: { total: num(hostsRow?.total), reporting: num(hostsRow?.reporting) },
    score: {
      start,
      end,
      trend: trend.map((r) => ({ day: iso(r.d).slice(0, 10), overall: optNum(r.o) ?? 0 })),
      lowest: lowest.map((r) => ({ agentId: str(r.agent_id), hostname: str(r.hostname), overall: optNum(r.o) ?? 0 })),
    },
    findings: {
      newBySev,
      resolvedBySev,
      openEndBySev,
      byScanner: byScanner.map((r) => ({ scanner: str(r.scanner), count: num(r.n) })),
      topRules: topRules.map((r) => ({ rule: str(r.rule), title: str(r.title), severity: SEVERITIES[num(r.r)] ?? 'info', count: num(r.n), hosts: num(r.hosts) })),
      topNew: topNew.map((r) => ({
        agentId: str(r.agent_id),
        hostname: str(r.hostname),
        severity: str(r.severity) as Sev,
        title: str(r.title),
        rule: str(r.rule),
        firstSeenAt: iso(r.first_seen_at),
      })),
    },
    intel: {
      hits: num(intelTot?.n),
      indicators: num(intelTot?.ind),
      hosts: num(intelTot?.hosts),
      byFeed: byFeed.map((r) => ({ vendor: str(r.vendor), feed: str(r.feed_name), hits: num(r.n) })),
      topIndicators: topInd.map((r) => ({ indicator: str(r.indicator), hits: num(r.n), hosts: num(r.hosts) })),
    },
    connections: {
      dangerous: num(connTot?.dangerous),
      suspicious: num(connTot?.suspicious),
      topIps: topIps.map((r) => ({
        ip: str(r.remote_ip),
        verdict: num(r.v) === 0 ? 'dangerous' : 'suspicious',
        seen: num(r.seen),
        hosts: num(r.hosts),
        country: r.country == null ? null : str(r.country),
        org: r.org == null ? null : str(r.org),
        process: r.process == null ? null : str(r.process),
        note: r.note == null ? null : str(r.note),
      })),
    },
    dns: {
      queries: num(dnsTot?.queries),
      nxdomain: num(dnsTot?.nx),
      domains: num(dnsTot?.domains),
      alerts: byScanner.filter((r) => str(r.scanner) === 'dns').reduce((s, r) => s + num(r.n), 0),
      blocked: num(dnsBlocked?.n),
      topBlocked: topBlocked.map((r) => ({ domain: str(r.registrable), count: num(r.n) })),
    },
    events: {
      total: num(evTot?.n),
      sources: num(evTot?.sources),
      byRule: evRules.map((r) => ({ rule: str(r.rule), count: num(r.n), hosts: num(r.hosts) })),
    },
    actions: {
      total: acts.reduce((s, r) => s + num(r.n), 0),
      byKind: acts.map((r) => ({ kind: str(r.kind), status: str(r.status), count: num(r.n) })),
      autoBlocks: num(autoBlocks?.n),
    },
    mitre,
  };
}

export function sevTotal(c: SevCounts): number {
  return SEVERITIES.reduce((s, k) => s + c[k], 0);
}
