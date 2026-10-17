// 每小時彙總＋保留期限：從原始樣本重算「有新資料進來的那幾個小時」（冪等，重跑結果一樣），
// 再刪掉超過保留天數的原始樣本與彙總。用 advisory lock，多個 hub 行程同時跑也只有一個在做。
import { and, eq, gt, gte, lt, sql } from 'drizzle-orm';
import { hostMetrics, hostMetricsHourly, settings, type MetricDisk, type MetricIface, type MetricProcNet } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';

const WATERMARK = 'metrics.rollup_watermark';
/** 交易可能比 received_at 晚提交：往回多看一點。 */
const OVERLAP_MS = 5 * 60_000;
const HOUR = 3_600_000;
/** 每小時彙總最多保留幾個介面／程式。 */
const MAX_IFACES = 24;
const MAX_PROCS = 10;

type RawRow = typeof hostMetrics.$inferSelect;

export function hourOf(d: Date): Date {
  return new Date(Math.floor(d.getTime() / HOUR) * HOUR);
}

/** 一小時的原始樣本 → 彙總列（純函式）。 */
export function aggregateHour(agentId: string, hour: Date, rows: RawRow[]) {
  const sorted = [...rows].sort((a, b) => a.at.getTime() - b.at.getTime());
  const ifaces = new Map<string, MetricIface>();
  const procs = new Map<string, MetricProcNet>();
  let rx = 0;
  let tx = 0;
  let seconds = 0;
  let hasProcs = false;
  for (const r of sorted) {
    rx += r.rxBytes;
    tx += r.txBytes;
    seconds += r.intervalS;
    for (const i of r.interfaces ?? []) {
      const e = ifaces.get(i.name) ?? { name: i.name, virtual: i.virtual, rx: 0, tx: 0 };
      e.rx += i.rx;
      e.tx += i.tx;
      e.virtual = e.virtual || i.virtual;
      ifaces.set(i.name, e);
    }
    if (r.processes) {
      hasProcs = true;
      for (const p of r.processes) {
        const e = procs.get(p.name) ?? { name: p.name, rx: 0, tx: 0 };
        e.rx += p.rx;
        e.tx += p.tx;
        procs.set(p.name, e);
      }
    }
  }
  const perf = sorted.filter((r) => r.perf);
  const nums = (f: (r: RawRow) => number | null | undefined) => perf.map(f).filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
  const avg = (v: number[]) => (v.length ? v.reduce((a, b) => a + b, 0) / v.length : null);
  const max = (v: number[]) => (v.length ? Math.max(...v) : null);
  const sum = (v: number[]) => (v.length ? v.reduce((a, b) => a + b, 0) : null);
  const lastPerf = perf[perf.length - 1];
  const battery = perf.map((r) => r.battery?.percent).filter((v): v is number => typeof v === 'number');
  const memAvg = avg(nums((r) => r.memUsed));
  const byTotal = <T extends { rx: number; tx: number }>(a: T, b: T) => b.rx + b.tx - (a.rx + a.tx);
  return {
    agentId,
    hour,
    samples: sorted.length,
    seconds,
    rxBytes: rx,
    txBytes: tx,
    interfaces: [...ifaces.values()].sort(byTotal).slice(0, MAX_IFACES),
    processes: hasProcs ? [...procs.values()].filter((p) => p.rx + p.tx > 0).sort(byTotal).slice(0, MAX_PROCS) : null,
    perfSamples: perf.length,
    cpuAvg: avg(nums((r) => r.cpuPct)),
    cpuMax: max(nums((r) => r.cpuPct)),
    memUsedAvg: memAvg == null ? null : Math.round(memAvg),
    memUsedMax: max(nums((r) => r.memUsed)),
    memTotal: lastPerf?.memTotal ?? null,
    swapUsedMax: max(nums((r) => r.swapUsed)),
    swapTotal: lastPerf?.swapTotal ?? null,
    diskUsedPctMax: max(nums((r) => r.diskUsedPct)),
    disks: (lastPerf?.disks as MetricDisk[] | null | undefined) ?? null,
    diskRead: sum(nums((r) => r.diskRead)),
    diskWrite: sum(nums((r) => r.diskWrite)),
    load1Avg: avg(nums((r) => r.load1)),
    batteryMin: battery.length ? Math.min(...battery) : null,
    batteryLast: battery.length ? battery[battery.length - 1] : null,
    updatedAt: new Date(),
  };
}

export interface RollupResult {
  skipped: boolean;
  hours: number;
  deletedRaw: number;
  deletedHourly: number;
}

async function watermark(db: DB): Promise<Date> {
  const [row] = await db.select().from(settings).where(eq(settings.key, WATERMARK)).limit(1);
  const v = typeof row?.value === 'string' ? Date.parse(row.value) : NaN;
  return Number.isFinite(v) ? new Date(v) : new Date(0);
}

/** 跑一次彙總與清理。另一個行程正在跑就直接回 `skipped`。 */
export async function rollupMetrics(db: DB, now = new Date()): Promise<RollupResult> {
  return db.transaction(async (tx) => {
    const t = tx as unknown as DB;
    const lock = await t.execute(sql`select pg_try_advisory_xact_lock(hashtext('asa_hub.metrics_rollup')) as ok`);
    const rows = (lock as unknown as { rows: { ok: boolean }[] }).rows ?? (lock as unknown as { ok: boolean }[]);
    if (!rows[0]?.ok) return { skipped: true, hours: 0, deletedRaw: 0, deletedHourly: 0 };
    const e = env();
    const since = new Date((await watermark(t)).getTime() - OVERLAP_MS);
    // 有新樣本進來的（主機, 小時）
    const touched = await t
      .selectDistinct({ agentId: hostMetrics.agentId, hour: sql<string>`date_trunc('hour', ${hostMetrics.at})`.as('hour') })
      .from(hostMetrics)
      .where(gt(hostMetrics.receivedAt, since));
    const byAgent = new Map<string, Date[]>();
    for (const r of touched) {
      const h = hourOf(new Date(r.hour));
      byAgent.set(r.agentId, [...(byAgent.get(r.agentId) ?? []), h]);
    }
    let hours = 0;
    for (const [agentId, list] of byAgent) {
      const from = new Date(Math.min(...list.map((d) => d.getTime())));
      const to = new Date(Math.max(...list.map((d) => d.getTime())) + HOUR);
      const raw = await t
        .select()
        .from(hostMetrics)
        .where(and(eq(hostMetrics.agentId, agentId), gte(hostMetrics.at, from), lt(hostMetrics.at, to)));
      const want = new Set(list.map((d) => d.getTime()));
      const groups = new Map<number, RawRow[]>();
      for (const r of raw) {
        const h = hourOf(r.at).getTime();
        if (!want.has(h)) continue;
        groups.set(h, [...(groups.get(h) ?? []), r]);
      }
      for (const [h, rs] of groups) {
        const row = aggregateHour(agentId, new Date(h), rs);
        const { agentId: _a, hour: _h, ...set } = row;
        await t.insert(hostMetricsHourly).values(row).onConflictDoUpdate({ target: [hostMetricsHourly.agentId, hostMetricsHourly.hour], set });
        hours++;
      }
    }
    const rawCut = new Date(now.getTime() - e.metricsRawDays * 86_400_000);
    const hourlyCut = new Date(now.getTime() - e.metricsHourlyDays * 86_400_000);
    const delRaw = await t.delete(hostMetrics).where(lt(hostMetrics.at, rawCut)).returning({ a: hostMetrics.agentId });
    const delHourly = await t.delete(hostMetricsHourly).where(lt(hostMetricsHourly.hour, hourlyCut)).returning({ a: hostMetricsHourly.agentId });
    await t
      .insert(settings)
      .values({ key: WATERMARK, value: now.toISOString(), updatedBy: 'metrics-rollup' })
      .onConflictDoUpdate({ target: settings.key, set: { value: now.toISOString(), updatedAt: now } });
    return { skipped: false, hours, deletedRaw: delRaw.length, deletedHourly: delHourly.length };
  });
}

const g = globalThis as unknown as { __asaMetricsTimer?: ReturnType<typeof setInterval>; __asaMetricsSoon?: ReturnType<typeof setTimeout>; __asaMetricsRunning?: boolean };

async function runSafely(): Promise<void> {
  if (g.__asaMetricsRunning) return;
  g.__asaMetricsRunning = true;
  try {
    const { getDb } = await import('@/lib/db');
    await rollupMetrics(getDb());
    // 同一支排程順便清超過保留期限的 AI 分析紀錄與外部情資快取
    const { pruneHistory } = await import('@/lib/history');
    await pruneHistory(getDb());
  } catch (err) {
    console.warn('[ai-security-monitor-hub] metrics rollup failed', err instanceof Error ? err.message : err);
  } finally {
    g.__asaMetricsRunning = false;
  }
}

/** Hub 啟動時呼叫：每 10 分鐘彙總一次（第一次在 30 秒後）。 */
export function startMetricsScheduler(everyMs = 10 * 60_000): void {
  if (g.__asaMetricsTimer) return;
  g.__asaMetricsTimer = setInterval(() => void runSafely(), everyMs);
  g.__asaMetricsTimer.unref?.();
  setTimeout(() => void runSafely(), 30_000).unref?.();
}

/** 收到樣本後：1 分鐘內彙總一次（多次觸發合併成一次），圖表的 7 天／30 天不用等到下一個 10 分鐘。 */
export function rollupSoon(delayMs = 60_000): void {
  if (g.__asaMetricsSoon) return;
  g.__asaMetricsSoon = setTimeout(() => {
    g.__asaMetricsSoon = undefined;
    void runSafely();
  }, delayMs);
  g.__asaMetricsSoon.unref?.();
}
