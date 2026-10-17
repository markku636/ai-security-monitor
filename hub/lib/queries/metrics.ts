// 網路流量與效能查詢：1 小時／24 小時用原始樣本（每分鐘），7 天／30 天用每小時彙總。
import { and, desc, eq, isNull, sql, type SQL } from 'drizzle-orm';
import { agents, hostMetrics, hostMetricsHourly, type MetricBattery, type MetricDisk, type MetricProcPerf } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { env } from '@/lib/env';
import { getParam, type Params } from './params';

export const RANGES = ['1h', '24h', '7d', '30d'] as const;
export type Range = (typeof RANGES)[number];

export const RANGE_SPEC: Record<Range, { ms: number; bucketS: number; source: 'raw' | 'hourly' }> = {
  '1h': { ms: 3_600_000, bucketS: 60, source: 'raw' },
  '24h': { ms: 86_400_000, bucketS: 900, source: 'raw' },
  '7d': { ms: 7 * 86_400_000, bucketS: 3600, source: 'hourly' },
  '30d': { ms: 30 * 86_400_000, bucketS: 6 * 3600, source: 'hourly' },
};

export function parseRange(p: Params, key = 'range', dflt: Range = '24h'): Range {
  const v = getParam(p, key);
  return (RANGES as readonly string[]).includes(v ?? '') ? (v as Range) : dflt;
}

type Row = Record<string, unknown>;
function rowsOf(r: unknown): Row[] {
  if (Array.isArray(r)) return r as Row[];
  return ((r as { rows?: Row[] })?.rows ?? []) as Row[];
}
const num = (v: unknown): number => (v == null ? 0 : Number(v));
const opt = (v: unknown): number | null => (v == null ? null : Number(v));

/** 依範圍挑資料表：原始樣本保留天數涵蓋得到就用原始樣本（最即時），否則用每小時彙總。 */
function sourceFor(ms: number, preferred: 'raw' | 'hourly'): 'raw' | 'hourly' {
  if (preferred === 'hourly') return 'hourly';
  return ms <= env().metricsRawDays * 86_400_000 ? 'raw' : 'hourly';
}

function table(src: 'raw' | 'hourly'): { t: SQL; at: SQL } {
  return src === 'raw' ? { t: sql.raw('host_metrics'), at: sql.raw('m.at') } : { t: sql.raw('host_metrics_hourly'), at: sql.raw('m.hour') };
}

/** 從 since 到 now 的每個 bucket 起點（秒）。 */
export function buckets(sinceMs: number, nowMs: number, bucketS: number): number[] {
  const step = bucketS * 1000;
  const out: number[] = [];
  for (let t = Math.floor(sinceMs / step) * step; t <= nowMs; t += step) out.push(t);
  return out;
}

export interface BandwidthPoint {
  t: string;
  /** 平均速率 bytes/s；沒有資料是 null。 */
  rx: number | null;
  tx: number | null;
}

/** 頻寬（所有主機加總或單一主機）：每個 bucket 的平均下載／上傳速率。 */
export async function bandwidthSeries(range: Range, agentId?: string, now = new Date()) {
  const spec = RANGE_SPEC[range];
  const src = sourceFor(spec.ms, spec.source);
  const { t, at } = table(src);
  const since = new Date(now.getTime() - spec.ms);
  const res = await getDb().execute(sql`
    select floor(extract(epoch from ${at}) / ${spec.bucketS})::bigint * ${spec.bucketS} as b,
           sum(m.rx_bytes)::float8 as rx, sum(m.tx_bytes)::float8 as tx
    from ${t} m join agents a on a.id = m.agent_id and a.deleted_at is null
    where ${at} >= ${since.toISOString()}::timestamptz ${agentId ? sql`and m.agent_id = ${agentId}` : sql``}
    group by 1 order by 1`);
  const map = new Map(rowsOf(res).map((r) => [num(r.b) * 1000, r]));
  let totalRx = 0;
  let totalTx = 0;
  const points: BandwidthPoint[] = buckets(since.getTime(), now.getTime(), spec.bucketS).map((b) => {
    const r = map.get(b);
    if (!r) return { t: new Date(b).toISOString(), rx: null, tx: null };
    totalRx += num(r.rx);
    totalTx += num(r.tx);
    return { t: new Date(b).toISOString(), rx: num(r.rx) / spec.bucketS, tx: num(r.tx) / spec.bucketS };
  });
  return { range, bucketS: spec.bucketS, points, totalRx, totalTx, hasData: map.size > 0 };
}

export interface HostTraffic {
  agentId: string;
  hostname: string;
  osFamily: string;
  rx24h: number;
  tx24h: number;
  rx7d: number;
  tx7d: number;
}

/** 流量最多的主機（24 小時與 7 天）。 */
export async function hostTrafficRanking(limit = 20, now = new Date()): Promise<HostTraffic[]> {
  const d1 = new Date(now.getTime() - 86_400_000).toISOString();
  const src = sourceFor(7 * 86_400_000, 'raw');
  const { t, at } = table(src);
  const d7 = new Date(now.getTime() - 7 * 86_400_000).toISOString();
  const res = await getDb().execute(sql`
    select m.agent_id, a.hostname, a.os_family,
           coalesce(sum(m.rx_bytes) filter (where ${at} >= ${d1}::timestamptz), 0)::float8 as rx24,
           coalesce(sum(m.tx_bytes) filter (where ${at} >= ${d1}::timestamptz), 0)::float8 as tx24,
           sum(m.rx_bytes)::float8 as rx7, sum(m.tx_bytes)::float8 as tx7
    from ${t} m join agents a on a.id = m.agent_id and a.deleted_at is null
    where ${at} >= ${d7}::timestamptz
    group by 1, 2, 3
    order by sum(m.rx_bytes) + sum(m.tx_bytes) desc
    limit ${Math.min(limit, 200)}`);
  return rowsOf(res).map((r) => ({
    agentId: String(r.agent_id),
    hostname: String(r.hostname),
    osFamily: String(r.os_family ?? ''),
    rx24h: num(r.rx24),
    tx24h: num(r.tx24),
    rx7d: num(r.rx7),
    tx7d: num(r.tx7),
  }));
}

export interface IfaceTraffic {
  agentId: string;
  hostname: string;
  name: string;
  virtual: boolean;
  rx: number;
  tx: number;
}

/** 各介面的收發量（所有主機或單一主機）。 */
export async function interfaceBreakdown(range: Range, agentId?: string, limit = 40, now = new Date()): Promise<IfaceTraffic[]> {
  const spec = RANGE_SPEC[range];
  const { t, at } = table(sourceFor(spec.ms, spec.source));
  const since = new Date(now.getTime() - spec.ms).toISOString();
  const res = await getDb().execute(sql`
    select m.agent_id, a.hostname, i->>'name' as name, bool_or(coalesce((i->>'virtual')::boolean, false)) as virtual,
           sum((i->>'rx')::float8) as rx, sum((i->>'tx')::float8) as tx
    from ${t} m join agents a on a.id = m.agent_id and a.deleted_at is null
    cross join lateral jsonb_array_elements(m.interfaces) as i
    where ${at} >= ${since}::timestamptz ${agentId ? sql`and m.agent_id = ${agentId}` : sql``}
    group by 1, 2, 3
    having sum((i->>'rx')::float8) + sum((i->>'tx')::float8) > 0
    order by sum((i->>'rx')::float8) + sum((i->>'tx')::float8) desc
    limit ${limit}`);
  return rowsOf(res).map((r) => ({
    agentId: String(r.agent_id),
    hostname: String(r.hostname),
    name: String(r.name),
    virtual: r.virtual === true || r.virtual === 't',
    rx: num(r.rx),
    tx: num(r.tx),
  }));
}

export interface ProcTraffic {
  name: string;
  hosts: number;
  rx: number;
  tx: number;
}

/** 各程式的收發量（只有 Windows 以系統管理員執行、或 macOS 的主機有）。`hostsWithData`＝有提供的主機數。 */
export async function processTraffic(range: Range, agentId?: string, limit = 20, now = new Date()) {
  const spec = RANGE_SPEC[range];
  const { t, at } = table(sourceFor(spec.ms, spec.source));
  const since = new Date(now.getTime() - spec.ms).toISOString();
  const where = sql`${at} >= ${since}::timestamptz ${agentId ? sql`and m.agent_id = ${agentId}` : sql``}`;
  const db = getDb();
  const [rows, hosts] = await Promise.all([
    db.execute(sql`
      select p->>'name' as name, count(distinct m.agent_id)::int as hosts,
             sum((p->>'rx')::float8) as rx, sum((p->>'tx')::float8) as tx
      from ${t} m join agents a on a.id = m.agent_id and a.deleted_at is null
      cross join lateral jsonb_array_elements(m.processes) as p
      where m.processes is not null and ${where}
      group by 1
      order by sum((p->>'rx')::float8) + sum((p->>'tx')::float8) desc
      limit ${limit}`),
    db.execute(sql`
      select count(distinct m.agent_id) filter (where m.processes is not null)::int as with_data, count(distinct m.agent_id)::int as total
      from ${t} m join agents a on a.id = m.agent_id and a.deleted_at is null
      where ${where}`),
  ]);
  const h = rowsOf(hosts)[0] ?? {};
  return {
    rows: rowsOf(rows).map((r) => ({ name: String(r.name), hosts: num(r.hosts), rx: num(r.rx), tx: num(r.tx) })) as ProcTraffic[],
    hostsWithData: num(h.with_data),
    hostsTotal: num(h.total),
  };
}

export interface ProcSeries {
  /** 程式名稱；null＝其餘程式合併的「其他」。 */
  name: string | null;
  /** 每個 bucket 的平均速率 bytes/s；這段時間沒有任何主機回報各程式流量是 null。 */
  rx: (number | null)[];
  tx: (number | null)[];
  totalRx: number;
  totalTx: number;
}

/** 各程式流量的時間序列：這段期間流量最多的前 top 個程式各一條，其餘合併成「其他」（在 SQL 裡先合併，列數固定）。 */
export async function processSeries(range: Range, agentId?: string, top = 6, now = new Date()) {
  const spec = RANGE_SPEC[range];
  const { t, at } = table(sourceFor(spec.ms, spec.source));
  const since = new Date(now.getTime() - spec.ms);
  const res = await getDb().execute(sql`
    with s as (
      select floor(extract(epoch from ${at}) / ${spec.bucketS})::bigint * ${spec.bucketS} as b,
             p->>'name' as name, (p->>'rx')::float8 as rx, (p->>'tx')::float8 as tx
      from ${t} m join agents a on a.id = m.agent_id and a.deleted_at is null
      cross join lateral jsonb_array_elements(m.processes) as p
      where m.processes is not null and ${at} >= ${since.toISOString()}::timestamptz ${agentId ? sql`and m.agent_id = ${agentId}` : sql``}
    ), top as (
      select name, row_number() over (order by sum(rx + tx) desc, name) as rank
      from s group by name order by sum(rx + tx) desc, name limit ${top}
    )
    select s.b, top.name, min(top.rank) as rank, sum(s.rx)::float8 as rx, sum(s.tx)::float8 as tx
    from s left join top on top.name = s.name
    group by s.b, top.name`);
  const rows = rowsOf(res);
  const times = buckets(since.getTime(), now.getTime(), spec.bucketS);
  const index = new Map(times.map((b, i) => [b, i]));
  const withData = new Set(rows.map((r) => num(r.b) * 1000));
  const byName = new Map<string | null, { rank: number; rx: Map<number, number>; tx: Map<number, number> }>();
  for (const r of rows) {
    const name = r.name == null ? null : String(r.name);
    const e = byName.get(name) ?? { rank: name == null ? Number.MAX_SAFE_INTEGER : num(r.rank), rx: new Map(), tx: new Map() };
    const b = num(r.b) * 1000;
    if (index.has(b)) {
      e.rx.set(b, num(r.rx));
      e.tx.set(b, num(r.tx));
    }
    byName.set(name, e);
  }
  const series: ProcSeries[] = [...byName.entries()]
    .sort((x, y) => x[1].rank - y[1].rank)
    .map(([name, e]) => {
      // 有主機回報各程式流量、但這個程式沒出現的時段算 0；整段時間都沒人回報才是 null（圖上斷開）
      const vals = (m: Map<number, number>) => times.map((b) => (withData.has(b) ? (m.get(b) ?? 0) / spec.bucketS : null));
      return {
        name,
        rx: vals(e.rx),
        tx: vals(e.tx),
        totalRx: [...e.rx.values()].reduce((a, v) => a + v, 0),
        totalTx: [...e.tx.values()].reduce((a, v) => a + v, 0),
      };
    });
  return { range, bucketS: spec.bucketS, times: times.map((b) => new Date(b).toISOString()), series, hasData: withData.size > 0 };
}

export interface PerfPoint {
  t: string;
  cpu: number | null;
  cpuMax: number | null;
  memPct: number | null;
  diskPct: number | null;
  diskRead: number | null;
  diskWrite: number | null;
  rx: number | null;
  tx: number | null;
  battery: number | null;
}

/** 單一主機的效能與網路速率時間序列。 */
export async function hostPerfSeries(agentId: string, range: Range, now = new Date()) {
  const spec = RANGE_SPEC[range];
  const src = sourceFor(spec.ms, spec.source);
  const since = new Date(now.getTime() - spec.ms).toISOString();
  const db = getDb();
  const res =
    src === 'raw'
      ? await db.execute(sql`
          select floor(extract(epoch from at) / ${spec.bucketS})::bigint * ${spec.bucketS} as b,
                 avg(cpu_pct) as cpu, max(cpu_pct) as cpu_max,
                 avg(case when mem_total > 0 then mem_used::float8 * 100 / mem_total end) as mem_pct,
                 max(disk_used_pct) as disk_pct,
                 sum(disk_read)::float8 as dr, sum(disk_write)::float8 as dw,
                 sum(rx_bytes)::float8 as rx, sum(tx_bytes)::float8 as tx,
                 min((battery->>'percent')::int) as bat, bool_or(perf) as perf
          from host_metrics where agent_id = ${agentId} and at >= ${since}::timestamptz
          group by 1 order by 1`)
      : await db.execute(sql`
          select floor(extract(epoch from hour) / ${spec.bucketS})::bigint * ${spec.bucketS} as b,
                 avg(cpu_avg) as cpu, max(cpu_max) as cpu_max,
                 avg(case when mem_total > 0 then mem_used_avg::float8 * 100 / mem_total end) as mem_pct,
                 max(disk_used_pct_max) as disk_pct,
                 sum(disk_read)::float8 as dr, sum(disk_write)::float8 as dw,
                 sum(rx_bytes)::float8 as rx, sum(tx_bytes)::float8 as tx,
                 min(battery_min) as bat, bool_or(perf_samples > 0) as perf
          from host_metrics_hourly where agent_id = ${agentId} and hour >= ${since}::timestamptz
          group by 1 order by 1`);
  const map = new Map(rowsOf(res).map((r) => [num(r.b) * 1000, r]));
  const rate = (v: unknown) => (v == null ? null : num(v) / spec.bucketS);
  const points: PerfPoint[] = buckets(Date.parse(since), now.getTime(), spec.bucketS).map((b) => {
    const r = map.get(b);
    return {
      t: new Date(b).toISOString(),
      cpu: r ? opt(r.cpu) : null,
      cpuMax: r ? opt(r.cpu_max) : null,
      memPct: r ? opt(r.mem_pct) : null,
      diskPct: r ? opt(r.disk_pct) : null,
      diskRead: r ? rate(r.dr) : null,
      diskWrite: r ? rate(r.dw) : null,
      rx: r ? rate(r.rx) : null,
      tx: r ? rate(r.tx) : null,
      battery: r ? opt(r.bat) : null,
    };
  });
  const hasPerf = [...map.values()].some((r) => r.perf === true || r.perf === 't');
  return { range, bucketS: spec.bucketS, points, hasData: map.size > 0, hasPerf };
}

export interface LatestPerf {
  at: Date;
  intervalS: number;
  cpuPct: number | null;
  cpuCores: number | null;
  memUsed: number | null;
  memTotal: number | null;
  swapUsed: number | null;
  swapTotal: number | null;
  disks: MetricDisk[];
  diskRead: number | null;
  diskWrite: number | null;
  load1: number | null;
  uptimeS: number | null;
  topCpu: MetricProcPerf[];
  topMem: MetricProcPerf[];
  battery: MetricBattery | null;
}

/** 最新一個有效能資料的樣本。 */
export async function latestPerf(agentId: string): Promise<LatestPerf | null> {
  const [r] = await getDb()
    .select()
    .from(hostMetrics)
    .where(and(eq(hostMetrics.agentId, agentId), eq(hostMetrics.perf, true)))
    .orderBy(desc(hostMetrics.at))
    .limit(1);
  if (!r) return null;
  return {
    at: r.at,
    intervalS: r.intervalS,
    cpuPct: r.cpuPct,
    cpuCores: r.cpuCores,
    memUsed: r.memUsed,
    memTotal: r.memTotal,
    swapUsed: r.swapUsed,
    swapTotal: r.swapTotal,
    disks: r.disks ?? [],
    diskRead: r.diskRead,
    diskWrite: r.diskWrite,
    load1: r.load1,
    uptimeS: r.uptimeS,
    topCpu: r.topCpu ?? [],
    topMem: r.topMem ?? [],
    battery: r.battery ?? null,
  };
}

export interface PerfAlert {
  agentId: string;
  hostname: string;
  at: Date;
  cpu: number | null;
  memPct: number | null;
  diskPct: number | null;
  reasons: ('cpu' | 'mem' | 'disk')[];
}

export const ALERT_PCT = 90;

/** 資源吃緊的主機：最近 30 分鐘內最新的效能樣本 CPU、記憶體或任一磁碟 ≥ 90%。 */
export async function perfAlerts(now = new Date()): Promise<PerfAlert[]> {
  const since = new Date(now.getTime() - 30 * 60_000).toISOString();
  const res = await getDb().execute(sql`
    select distinct on (m.agent_id) m.agent_id, a.hostname, m.at, m.cpu_pct,
           case when m.mem_total > 0 then m.mem_used::float8 * 100 / m.mem_total end as mem_pct, m.disk_used_pct
    from host_metrics m join agents a on a.id = m.agent_id and a.deleted_at is null and a.perf_enabled = true
    where m.perf and m.at >= ${since}::timestamptz
    order by m.agent_id, m.at desc`);
  return rowsOf(res)
    .map((r) => {
      const cpu = opt(r.cpu_pct);
      const memPct = opt(r.mem_pct);
      const diskPct = opt(r.disk_used_pct);
      const reasons: PerfAlert['reasons'] = [];
      if ((cpu ?? 0) >= ALERT_PCT) reasons.push('cpu');
      if ((memPct ?? 0) >= ALERT_PCT) reasons.push('mem');
      if ((diskPct ?? 0) >= ALERT_PCT) reasons.push('disk');
      return { agentId: String(r.agent_id), hostname: String(r.hostname), at: r.at instanceof Date ? r.at : new Date(String(r.at)), cpu, memPct, diskPct, reasons };
    })
    .filter((a) => a.reasons.length > 0)
    .sort((a, b) => b.reasons.length - a.reasons.length || a.hostname.localeCompare(b.hostname));
}

/** 總覽：所有主機 24 小時的流量、有回報流量的主機數、開啟效能蒐集的主機數。 */
export async function trafficSummary(now = new Date()) {
  const since = new Date(now.getTime() - 86_400_000).toISOString();
  const db = getDb();
  const [tot, hosts] = await Promise.all([
    db.execute(sql`
      select coalesce(sum(m.rx_bytes), 0)::float8 as rx, coalesce(sum(m.tx_bytes), 0)::float8 as tx, count(distinct m.agent_id)::int as hosts
      from host_metrics m join agents a on a.id = m.agent_id and a.deleted_at is null
      where m.at >= ${since}::timestamptz`),
    db
      .select({ reporting: sql<number>`count(*) filter (where ${agents.metricsAt} is not null)::int`, perf: sql<number>`count(*) filter (where ${agents.perfEnabled})::int` })
      .from(agents)
      .where(isNull(agents.deletedAt)),
  ]);
  const t = rowsOf(tot)[0] ?? {};
  return { rx24h: num(t.rx), tx24h: num(t.tx), hosts24h: num(t.hosts), reporting: num(hosts[0]?.reporting), perfEnabled: num(hosts[0]?.perf) };
}

/** 每小時彙總筆數（設定頁與測試用）。 */
export async function hourlyCount(agentId?: string): Promise<number> {
  const q = getDb().select({ n: sql<number>`count(*)::int` }).from(hostMetricsHourly);
  const [r] = agentId ? await q.where(eq(hostMetricsHourly.agentId, agentId)) : await q;
  return num(r?.n);
}
