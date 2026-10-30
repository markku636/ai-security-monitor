// 網站掃描頁與設定頁要的資料（管理員 API 與頁面共用）。
import { and, eq, inArray, isNull, sql } from 'drizzle-orm';
import { webFindings, webTargets } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';
import { getIntelUsage } from '@/lib/intel/usage';
import { listWebFindings } from './findings';
import { getJobDetail, listJobs } from './jobs';
import { listRunners } from './runners';
import { getWebscanSettings } from './settings';
import { getTarget, listTargets, publicTarget } from './targets';

export async function webscanView(db: DB) {
  const [settings, runners, targets, jobs, usage] = await Promise.all([getWebscanSettings(db), listRunners(db), listTargets(db), listJobs(db, { limit: 30 }), getIntelUsage(db)]);
  return { settings, runners, targets, jobs, usage: usage.usage, composeTokenConfigured: !!env().webscanToken };
}
export type WebscanView = Awaited<ReturnType<typeof webscanView>>;

export async function targetDetail(db: DB, id: string) {
  const t = await getTarget(db, id);
  if (!t) return null;
  const [jobs, findings, runners] = await Promise.all([listJobs(db, { targetId: id, limit: 30 }), listWebFindings(db, { targetId: id, limit: 1000 }), listRunners(db)]);
  const latest = jobs.find((j) => j.kind === 'scan' && (j.status === 'succeeded' || j.status === 'failed'));
  return {
    target: publicTarget(t),
    jobs,
    latest: latest ? await getJobDetail(db, latest.id) : null,
    findings,
    runnersOnline: runners.filter((r) => r.online).length,
  };
}
export type TargetDetail = NonNullable<Awaited<ReturnType<typeof targetDetail>>>;

/** 側欄紅點：網站掃描未處理的嚴重＋高（已刪除的目標不算）。 */
export async function urgentWebFindings(db: DB): Promise<number> {
  const [{ n }] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(webFindings)
    .innerJoin(webTargets, eq(webTargets.id, webFindings.targetId))
    .where(and(eq(webFindings.status, 'open'), inArray(webFindings.severity, ['critical', 'high']), isNull(webTargets.deletedAt)));
  return Number(n);
}
