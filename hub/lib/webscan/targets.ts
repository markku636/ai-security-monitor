// 掃描目標：新增、列表、刪除。
import crypto from 'node:crypto';
import { and, desc, eq, inArray, isNull, sql } from 'drizzle-orm';
import { webFindings, webscanJobs, webTargets } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { WEBSCAN_OPEN_STATUSES } from './scanners';
import { parseTargetUrl, resolveAndScreen, type ScreenResult } from './scope';
import { getWebscanSettings } from './settings';

export const MAX_TARGETS = 500;

export type TargetRow = typeof webTargets.$inferSelect;

function hex(bytes: number): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export const newTargetId = () => `wt_${hex(8)}`;
export async function getTarget(db: DB, id: string): Promise<TargetRow | null> {
  return (await db.select().from(webTargets).where(and(eq(webTargets.id, id), isNull(webTargets.deletedAt))).limit(1))[0] ?? null;
}

export async function createTarget(
  db: DB,
  input: { url: string; name?: string },
  actor: string,
): Promise<{ target: TargetRow; screen: ScreenResult } | { error: string }> {
  const p = parseTargetUrl(input.url);
  if ('error' in p) return { error: p.error };
  const [{ n }] = await db.select({ n: sql<number>`count(*)::int` }).from(webTargets).where(isNull(webTargets.deletedAt));
  if (Number(n) >= MAX_TARGETS) return { error: 'too_many_targets' };
  const dup = await db.select({ id: webTargets.id }).from(webTargets).where(and(eq(webTargets.url, p.url), isNull(webTargets.deletedAt))).limit(1);
  if (dup.length) return { error: 'duplicate' };
  const screen = await resolveAndScreen(p.host, { internalCidrs: (await getWebscanSettings(db)).internal_cidrs });
  try {
    const [target] = await db
      .insert(webTargets)
      .values({
        id: newTargetId(),
        url: p.url,
        scheme: p.scheme,
        host: p.host,
        port: p.port,
        path: p.path,
        name: (input.name ?? '').trim().slice(0, 120),
        verifyToken: '', // Legacy NOT NULL column; ownership verification has been removed.
        createdBy: actor,
      })
      .returning();
    return { target, screen };
  } catch {
    return { error: 'duplicate' };
  }
}

export async function deleteTarget(db: DB, id: string): Promise<boolean> {
  const t = await getTarget(db, id);
  if (!t) return false;
  const now = new Date();
  await db.update(webTargets).set({ deletedAt: now }).where(eq(webTargets.id, id));
  await db
    .update(webscanJobs)
    .set({ status: 'cancelled', finishedAt: now, error: 'target_deleted' })
    .where(and(eq(webscanJobs.targetId, id), inArray(webscanJobs.status, WEBSCAN_OPEN_STATUSES)));
  return true;
}

/** 目標清單＋每個目標未處理問題的嚴重度計數。 */
export async function listTargets(db: DB) {
  const rows = await db.select().from(webTargets).where(isNull(webTargets.deletedAt)).orderBy(desc(webTargets.createdAt)).limit(MAX_TARGETS);
  const counts = await db
    .select({ targetId: webFindings.targetId, severity: webFindings.severity, n: sql<number>`count(*)::int` })
    .from(webFindings)
    .where(eq(webFindings.status, 'open'))
    .groupBy(webFindings.targetId, webFindings.severity);
  const by = new Map<string, Record<string, number>>();
  for (const c of counts) {
    const m = by.get(c.targetId) ?? {};
    m[c.severity] = Number(c.n);
    by.set(c.targetId, m);
  }
  return rows.map((r) => {
    const sev = by.get(r.id) ?? {};
    return {
      ...publicTarget(r),
      counts: { critical: sev.critical ?? 0, high: sev.high ?? 0, medium: sev.medium ?? 0, low: sev.low ?? 0, info: sev.info ?? 0 },
    };
  });
}

export function publicTarget(r: TargetRow) {
  return {
    id: r.id,
    url: r.url,
    scheme: r.scheme,
    host: r.host,
    port: r.port,
    path: r.path,
    name: r.name,
    fingerprint: r.fingerprint,
    lastScanAt: r.lastScanAt?.toISOString() ?? null,
    lastJobId: r.lastJobId,
    createdAt: r.createdAt.toISOString(),
    createdBy: r.createdBy,
  };
}
export type TargetListItem = Awaited<ReturnType<typeof listTargets>>[number];
