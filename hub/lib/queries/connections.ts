// 連線查詢（每個 agent 最新快照）：車隊級篩選、對內攻擊來源、危險目的地。
import { and, count, desc, eq, ilike, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import { agents, connections, destinations, ipNotes } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { cachedRiskMap } from '@/lib/ipintel/service';
import type { IpRisk } from '@/lib/ipintel/types';
import { clampInt, listParam, strParam, type Params } from './params';

export const DIRECTIONS = ['outbound', 'inbound', 'listening', 'local'] as const;
export const VERDICTS = ['dangerous', 'suspicious', 'unknown', 'safe'] as const;
export type Direction = (typeof DIRECTIONS)[number];
export type VerdictLevel = (typeof VERDICTS)[number];

export interface ConnectionFilter {
  agentId?: string;
  direction?: Direction[];
  verdict?: VerdictLevel[];
  feed?: string;
  country?: string;
  q?: string;
  limit: number;
  offset: number;
}

/** 查詢字串 → 篩選條件（不認得的值直接忽略）。 */
export function parseConnectionFilter(p: Params): ConnectionFilter {
  return {
    agentId: strParam(p, 'agent_id', 64),
    direction: listParam(p, 'direction', DIRECTIONS),
    verdict: listParam(p, 'verdict', VERDICTS),
    feed: strParam(p, 'feed', 64),
    country: strParam(p, 'country', 2)?.toUpperCase(),
    q: strParam(p, 'q', 100),
    limit: clampInt(p, 'limit', 100, 1, 200),
    offset: clampInt(p, 'offset', 0, 0, 100_000),
  };
}

export function likePattern(q: string): string {
  return `%${q.replace(/[%_\\]/g, (c) => `\\${c}`)}%`;
}

function where(f: ConnectionFilter, skip: { verdict?: boolean; direction?: boolean } = {}): SQL {
  const conds: SQL[] = [isNull(agents.deletedAt)];
  if (f.agentId) conds.push(eq(connections.agentId, f.agentId));
  if (!skip.direction && f.direction?.length) conds.push(inArray(connections.direction, f.direction));
  if (!skip.verdict && f.verdict?.length) conds.push(inArray(connections.verdict, f.verdict));
  if (f.feed) conds.push(sql`${connections.intelFeedIds} @> ${JSON.stringify([f.feed])}::jsonb`);
  if (f.country) conds.push(eq(connections.country, f.country));
  if (f.q) {
    const like = likePattern(f.q);
    conds.push(
      or(
        ilike(connections.remoteIp, like),
        ilike(connections.processName, like),
        ilike(connections.org, like),
        ilike(agents.hostname, like),
      )!,
    );
  }
  return and(...conds)!;
}

const VERDICT_ORDER = sql`case ${connections.verdict} when 'dangerous' then 0 when 'suspicious' then 1 when 'unknown' then 2 else 3 end`;

/** 判定理由（agent 的 Verdict.reasons；hub 只負責顯示）。 */
export interface Reason {
  type: string;
  // intel_hit
  feed_id?: string;
  name?: string;
  vendor?: string;
  confidence?: number;
  license?: string;
  license_url?: string;
  fetched_at?: string;
  source_url?: string;
  matched?: string;
  // anomaly
  kind?: string;
  detail?: string;
  // reputation / known_good / allowlisted
  provider?: string;
  score?: number;
  list?: string;
  entry_id?: string;
}

export async function listConnections(f: ConnectionFilter) {
  const db = getDb();
  const facet = (k: typeof connections.verdict | typeof connections.direction, skip: { verdict?: boolean; direction?: boolean }) =>
    db
      .select({ k, n: count() })
      .from(connections)
      .innerJoin(agents, eq(agents.id, connections.agentId))
      .where(where(f, skip))
      .groupBy(k);
  const [items, total, byVerdict, byDirection] = await Promise.all([
    db
      .select({
        id: connections.id,
        agentId: connections.agentId,
        hostname: agents.hostname,
        at: connections.at,
        proto: connections.proto,
        localIp: connections.localIp,
        localPort: connections.localPort,
        remoteIp: connections.remoteIp,
        remotePort: connections.remotePort,
        state: connections.state,
        direction: connections.direction,
        verdict: connections.verdict,
        reasons: connections.reasons,
        intelFeedIds: connections.intelFeedIds,
        pid: connections.pid,
        processName: connections.processName,
        exe: connections.exe,
        country: connections.country,
        asn: connections.asn,
        org: connections.org,
      })
      .from(connections)
      .innerJoin(agents, eq(agents.id, connections.agentId))
      .where(where(f))
      .orderBy(VERDICT_ORDER, connections.direction, connections.remoteIp, connections.id)
      .limit(f.limit)
      .offset(f.offset),
    db
      .select({ n: count() })
      .from(connections)
      .innerJoin(agents, eq(agents.id, connections.agentId))
      .where(where(f)),
    facet(connections.verdict, { verdict: true }),
    facet(connections.direction, { direction: true }),
  ]);
  const toMap = (rows: { k: string; n: number }[]) => Object.fromEntries(rows.map((r) => [r.k, Number(r.n)])) as Record<string, number>;
  return {
    items: items.map((r) => ({ ...r, reasons: (Array.isArray(r.reasons) ? r.reasons : []) as Reason[] })),
    total: Number(total[0]?.n ?? 0),
    facets: { verdict: toMap(byVerdict), direction: toMap(byDirection) },
  };
}

export type ConnectionRow = Awaited<ReturnType<typeof listConnections>>['items'][number];

/**
 * 對內攻擊來源：目前連進來（inbound）且判定為可疑／危險的遠端 IP，跨主機彙總。
 * 之後事件引擎（失敗登入爆量）的來源也會併進來。
 */
export async function inboundAttackers(limit = 20) {
  const rows = await getDb()
    .select({
      remoteIp: sql<string>`${connections.remoteIp}`,
      worst: sql<number>`min(${VERDICT_ORDER})::int`,
      hosts: sql<number>`count(distinct ${connections.agentId})::int`,
      conns: sql<number>`count(*)::int`,
      ports: sql<number[]>`array_agg(distinct ${connections.localPort})`,
      country: sql<string | null>`max(${connections.country})`,
      org: sql<string | null>`max(${connections.org})`,
      feeds: sql<string[][]>`jsonb_agg(${connections.intelFeedIds})`,
    })
    .from(connections)
    .innerJoin(agents, and(eq(agents.id, connections.agentId), isNull(agents.deletedAt)))
    .where(
      and(
        eq(connections.direction, 'inbound'),
        inArray(connections.verdict, ['dangerous', 'suspicious']),
        sql`${connections.remoteIp} is not null`,
      ),
    )
    .groupBy(connections.remoteIp)
    .orderBy(sql`min(${VERDICT_ORDER})`, desc(sql`count(*)`))
    .limit(limit);
  return rows.map((r) => ({
    ...r,
    worst: (r.worst === 0 ? 'dangerous' : 'suspicious') as VerdictLevel,
    ports: (r.ports ?? []).slice(0, 10),
    feeds: [...new Set((r.feeds ?? []).flat())],
  }));
}

const DEST_WORST = sql`min(case ${destinations.worstVerdict} when 'dangerous' then 0 else 1 end)`;

/** 排名表可排序的欄位（表頭點了就換）。 */
export const RANK_SORT_KEYS = ['verdict', 'risk', 'ip', 'seen', 'live', 'hosts', 'port', 'process', 'geo', 'note', 'last'] as const;
export type RankSortKey = (typeof RANK_SORT_KEYS)[number];
export interface RankSort {
  key: RankSortKey;
  dir: 'asc' | 'desc';
}
/** 文字欄位第一次點是 A→Z，數字與時間是大→小。 */
export const RANK_SORT_DEFAULT_DIR: Record<RankSortKey, 'asc' | 'desc'> = {
  verdict: 'desc',
  risk: 'desc',
  ip: 'asc',
  seen: 'desc',
  live: 'desc',
  hosts: 'desc',
  port: 'asc',
  process: 'asc',
  geo: 'asc',
  note: 'asc',
  last: 'desc',
};

/** 查詢字串 rsort／rdir → 排序；沒給或不認得就是預設（危險程度，再看累計次數）。 */
export function parseRankSort(p: Params): RankSort {
  const key = listParam(p, 'rsort', RANK_SORT_KEYS)[0] ?? 'verdict';
  const dir = listParam(p, 'rdir', ['asc', 'desc'] as const)[0] ?? RANK_SORT_DEFAULT_DIR[key];
  return { key, dir };
}

/** 依外部風險排序時最多先撈幾個 IP 在記憶體裡排（分數是用快取的外部情資即時算的，SQL 排不了）。 */
const RISK_SORT_CAP = 2000;

/**
 * 可疑／危險 IP 排名：長期目的地表依遠端 IP 跨主機、跨 port 彙總。
 * seen＝被快照看到的累計次數（每次快照每個 ip:port:方向 算一次），live＝最新快照裡仍判定可疑／危險的條數。
 */
export async function riskyIpRanking(limit = 10, agentId?: string, sort: RankSort = { key: 'verdict', dir: 'desc' }) {
  const db = getDb();
  const conds: SQL[] = [isNull(agents.deletedAt), inArray(destinations.worstVerdict, ['dangerous', 'suspicious'])];
  if (agentId) conds.push(eq(destinations.agentId, agentId));
  // 目前條數用相關子查詢算，才能拿來排序（同一層的 agents 會被子查詢自己的 agents 遮住）
  const live = sql<number>`(select count(*) from ${connections} inner join ${agents} on ${agents.id} = ${connections.agentId}
    where ${agents.deletedAt} is null and ${connections.remoteIp} = ${destinations.remoteIp}
    and ${connections.verdict} in ('dangerous', 'suspicious')${agentId ? sql` and ${connections.agentId} = ${agentId}` : sql``})::int`;
  const seen = sql`sum(${destinations.seenCount})`;
  const sortExpr: Record<RankSortKey, SQL> = {
    verdict: sql`(1 - ${DEST_WORST})`,
    // 外部風險在下面用快取算完再排；SQL 先用預設順序
    risk: sql`(1 - ${DEST_WORST})`,
    ip: sql`${destinations.remoteIp}::inet`,
    seen,
    live,
    hosts: sql`count(distinct ${destinations.agentId})`,
    port: sql`min(${destinations.remotePort})`,
    process: sql`min(${destinations.processName})`,
    geo: sql`max(${destinations.country}) || ' ' || coalesce(max(${destinations.org}), '')`,
    note: sql`max(${ipNotes.note})`,
    last: sql`max(${destinations.lastSeenAt})`,
  };
  const byRisk = sort.key === 'risk';
  const primary = byRisk
    ? sql`${sortExpr.risk} desc`
    : sort.dir === 'asc'
      ? sql`${sortExpr[sort.key]} asc nulls last`
      : sql`${sortExpr[sort.key]} desc nulls last`;
  const [rows, total] = await Promise.all([
    db
      .select({
        remoteIp: destinations.remoteIp,
        worst: sql<number>`${DEST_WORST}::int`,
        seen: sql<number>`sum(${destinations.seenCount})::int`,
        hosts: sql<number>`count(distinct ${destinations.agentId})::int`,
        ports: sql<number[]>`array_agg(distinct ${destinations.remotePort})`,
        directions: sql<string[]>`array_agg(distinct ${destinations.direction})`,
        processes: sql<(string | null)[]>`array_agg(distinct ${destinations.processName})`,
        country: sql<string | null>`max(${destinations.country})`,
        org: sql<string | null>`max(${destinations.org})`,
        firstSeenAt: sql<string>`min(${destinations.firstSeenAt})`,
        lastSeenAt: sql<string>`max(${destinations.lastSeenAt})`,
        live,
        note: sql<string | null>`max(${ipNotes.note})`,
      })
      .from(destinations)
      .innerJoin(agents, eq(agents.id, destinations.agentId))
      .leftJoin(ipNotes, eq(ipNotes.ip, destinations.remoteIp))
      .where(and(...conds))
      .groupBy(destinations.remoteIp)
      .orderBy(primary, DEST_WORST, desc(seen), desc(sql`max(${destinations.lastSeenAt})`), destinations.remoteIp)
      .limit(byRisk ? RISK_SORT_CAP : limit),
    db
      .select({ n: sql<number>`count(distinct ${destinations.remoteIp})::int` })
      .from(destinations)
      .innerJoin(agents, eq(agents.id, destinations.agentId))
      .where(and(...conds)),
  ]);
  const risks = await cachedRiskMap(rows.map((r) => r.remoteIp));
  const riskOf = (ip: string): IpRisk => risks.get(ip) ?? { kind: 'unqueried' };
  let picked = rows;
  if (byRisk) {
    // 沒查過／內網的一律排最後；同分維持預設順序（Array.sort 是穩定的）
    const val = (ip: string) => {
      const r = riskOf(ip);
      return r.kind === 'scored' ? r.score : null;
    };
    picked = [...rows]
      .sort((a, b) => {
        const x = val(a.remoteIp);
        const y = val(b.remoteIp);
        if (x === y) return 0;
        if (x === null) return 1;
        if (y === null) return -1;
        return sort.dir === 'asc' ? x - y : y - x;
      })
      .slice(0, limit);
  }
  return {
    total: Number(total[0]?.n ?? 0),
    items: picked.map((r, i) => ({
      rank: i + 1,
      remoteIp: r.remoteIp,
      risk: riskOf(r.remoteIp),
      worst: (r.worst === 0 ? 'dangerous' : 'suspicious') as VerdictLevel,
      seen: Number(r.seen),
      live: Number(r.live ?? 0),
      hosts: Number(r.hosts),
      ports: [...(r.ports ?? [])].sort((a, b) => a - b).slice(0, 8),
      directions: r.directions ?? [],
      processes: (r.processes ?? []).filter((p): p is string => !!p).slice(0, 5),
      country: r.country,
      org: r.org,
      firstSeenAt: r.firstSeenAt,
      lastSeenAt: r.lastSeenAt,
      note: r.note ?? null,
    })),
  };
}

export type RiskyIpRanking = Awaited<ReturnType<typeof riskyIpRanking>>;

/** 看過的危險／可疑目的地（長期彙總表，不只最新快照）。 */
export async function riskyDestinations(limit = 10, agentId?: string) {
  const conds: SQL[] = [isNull(agents.deletedAt), inArray(destinations.worstVerdict, ['dangerous', 'suspicious'])];
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
      lastSeenAt: destinations.lastSeenAt,
      seenCount: destinations.seenCount,
    })
    .from(destinations)
    .innerJoin(agents, eq(agents.id, destinations.agentId))
    .where(and(...conds))
    .orderBy(sql`case ${destinations.worstVerdict} when 'dangerous' then 0 else 1 end`, desc(destinations.lastSeenAt))
    .limit(limit);
}
