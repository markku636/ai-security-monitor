// 寫入網路流量／效能樣本：(agent_id, at) 唯一，重送（agent 的離線佇列）不會重複計算；太舊的樣本（超過原始資料保留天數）略過。
import { eq, sql } from 'drizzle-orm';
import { agents, hostMetrics, type MetricDisk, type MetricProcPerf } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';
import { IngestRejected } from '@/lib/ingest/guard';
import type { MetricsBatchT, MetricSampleT } from '@/lib/ingest/schema';
import { evaluateMetricFindings } from './findings';

export interface MetricsResult {
  stored: number;
  duplicate: number;
  stale: number;
  performance: boolean;
}

const procPerf = (list: { name: string; pid?: number | null; count: number; cpu_pct: number; rss: number }[]): MetricProcPerf[] =>
  list.map((p) => ({ name: p.name, pid: p.pid ?? null, count: p.count, cpu: p.cpu_pct, rss: p.rss }));

/** 一個樣本 → 一列。`at` 已經處理過（未來時間夾到現在）。 */
export function rowOf(agentId: string, s: MetricSampleT, at: Date) {
  const p = s.perf ?? null;
  const disks: MetricDisk[] | null = p ? p.disks.map((d) => ({ mount: d.mount, fs: d.fs, used: d.used, total: d.total, removable: d.removable })) : null;
  const pct = disks?.filter((d) => d.total > 0).map((d) => (d.used / d.total) * 100) ?? [];
  return {
    agentId,
    at,
    intervalS: s.interval_s,
    rxBytes: s.net.rx_bytes,
    txBytes: s.net.tx_bytes,
    interfaces: s.net.interfaces.map((i) => ({ name: i.name, virtual: i.virtual, rx: i.rx_bytes, tx: i.tx_bytes })),
    processes: s.net.processes ? s.net.processes.map((x) => ({ name: x.name, rx: x.rx_bytes, tx: x.tx_bytes })) : null,
    perf: !!p,
    cpuPct: p?.cpu_pct ?? null,
    cpuCores: p?.cpu_cores ?? null,
    memUsed: p?.mem_used ?? null,
    memTotal: p?.mem_total ?? null,
    swapUsed: p?.swap_used ?? null,
    swapTotal: p?.swap_total ?? null,
    disks,
    diskUsedPct: pct.length ? Math.max(...pct) : null,
    diskRead: p?.disk_read_bytes ?? null,
    diskWrite: p?.disk_write_bytes ?? null,
    load1: p?.load?.[0] ?? null,
    uptimeS: p?.uptime_s ?? null,
    topCpu: p ? procPerf(p.top_cpu) : null,
    topMem: p ? procPerf(p.top_mem) : null,
    battery: p?.battery ? { percent: p.battery.percent, charging: p.battery.charging, plugged: p.battery.plugged ?? null } : null,
  };
}

export async function applyMetrics(db: DB, b: MetricsBatchT, now = new Date()): Promise<MetricsResult> {
  const [known] = await db.select({ deletedAt: agents.deletedAt, metricsAt: agents.metricsAt }).from(agents).where(eq(agents.id, b.agent_id)).limit(1);
  if (!known) throw new IngestRejected(409, 'register_first');
  if (known.deletedAt) throw new IngestRejected(410, 'agent_deleted');
  const oldest = now.getTime() - env().metricsRawDays * 86_400_000;
  let stale = 0;
  const rows = [];
  const seen = new Set<number>();
  for (const s of b.samples) {
    let t = Date.parse(s.ts);
    if (t < oldest) {
      stale++;
      continue;
    }
    // 時鐘超前：夾到現在
    if (t > now.getTime()) t = now.getTime();
    if (seen.has(t)) continue;
    seen.add(t);
    rows.push(rowOf(b.agent_id, s, new Date(t)));
  }
  let stored = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const ins = await db.insert(hostMetrics).values(rows.slice(i, i + 200)).onConflictDoNothing().returning({ at: hostMetrics.at });
    stored += ins.length;
  }
  const newest = rows.reduce<Date | null>((m, r) => (!m || r.at > m ? r.at : m), null);
  await db
    .update(agents)
    .set({
      perfEnabled: b.performance,
      lastSeenAt: now,
      ...(newest && (!known.metricsAt || newest > known.metricsAt) ? { metricsAt: newest } : {}),
    })
    .where(eq(agents.id, b.agent_id));
  if (stored > 0 || !b.performance) await evaluateMetricFindings(db, b.agent_id, b.performance, now);
  return { stored, duplicate: rows.length - stored, stale, performance: b.performance };
}

/** 測試與管理用：這台主機有幾筆原始樣本。 */
export async function rawCount(db: DB, agentId: string): Promise<number> {
  const [r] = await db.select({ n: sql<number>`count(*)::int` }).from(hostMetrics).where(eq(hostMetrics.agentId, agentId));
  return Number(r?.n ?? 0);
}
