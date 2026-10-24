// 網站掃描的發現：寫入、去重、跟上一次比對（語意比照 lib/ingest/apply.ts 的主機發現）。
//   新的 → open；重新出現（之前 resolved）→ 重新開啟；acked 但嚴重度升高 → 重新開啟；忽略到期 → 重新開啟
//   這次有跑的掃描器、上次有但這次沒看到 → resolved（掃描器這次失敗的不算，免得一次失敗就把問題全標成已解決）
import crypto from 'node:crypto';
import { and, desc, eq, inArray, isNull, sql, type SQL } from 'drizzle-orm';
import { webFindings, webTargets } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { SEVERITY_RANK, type NormalizedFinding, type Severity } from './parse/types';
import { WEB_FINDING_STATUSES, type WebFindingStatus } from './scanners';

/** finding_id 的演算法版本：改了 key 的組法就要加一，舊資料靠這個辨認。 */
export const FINGERPRINT_VER = 1;

export function findingIdOf(key: string): string {
  return `wf_${crypto.createHash('sha256').update(`v${FINGERPRINT_VER}|${key}`).digest('hex').slice(0, 16)}`;
}

function contentHash(f: Pick<NormalizedFinding, 'severity' | 'title' | 'detail'>): string {
  return crypto.createHash('sha256').update(JSON.stringify([f.severity, f.title, f.detail])).digest('hex');
}

const rank = (s: string) => SEVERITY_RANK[s as Severity] ?? 0;

export interface ApplySummary {
  new: number;
  reopened: number;
  resolved: number;
  open: number;
}

export async function applyScanFindings(
  db: DB,
  targetId: string,
  jobId: string,
  found: NormalizedFinding[],
  scannersCompleted: string[],
  now = new Date(),
): Promise<ApplySummary> {
  const incoming = new Map<string, NormalizedFinding>();
  for (const f of found) incoming.set(findingIdOf(f.key), f);
  const existing = scannersCompleted.length
    ? await db.select().from(webFindings).where(and(eq(webFindings.targetId, targetId), inArray(webFindings.scanner, scannersCompleted)))
    : [];
  const byId = new Map(existing.map((e) => [e.findingId, e]));
  let created = 0;
  let reopened = 0;
  const inserts: (typeof webFindings.$inferInsert)[] = [];
  for (const [findingId, f] of incoming) {
    const base = {
      scanner: f.scanner,
      rule: f.rule.slice(0, 200),
      severity: f.severity,
      title: f.title.slice(0, 300),
      detail: f.detail.slice(0, 4000),
      recommendation: f.recommendation.slice(0, 4000),
      location: f.location,
      evidence: f.evidence,
      cve: f.cve,
      cwe: f.cwe,
      cvss: f.cvss,
      refs: f.refs,
      tags: f.tags,
      contentHash: contentHash(f),
      lastSeenAt: now,
      lastJobId: jobId,
      fingerprintVer: FINGERPRINT_VER,
    };
    const e = byId.get(findingId);
    if (!e) {
      created++;
      inserts.push({ targetId, findingId, ...base, status: 'open', firstSeenAt: now, firstJobId: jobId });
      continue;
    }
    const suppressionOver = e.status === 'suppressed' && !!e.suppressedUntil && e.suppressedUntil.getTime() < now.getTime();
    const worse = e.status === 'acked' && rank(f.severity) > rank(e.severity);
    const reopen = e.status === 'resolved' || suppressionOver || worse;
    if (reopen) reopened++;
    await db
      .update(webFindings)
      .set({ ...base, ...(reopen ? { status: 'open', resolvedAt: null, ackedAt: null, ackedBy: null, suppressedUntil: null, suppressReason: null } : {}) })
      .where(and(eq(webFindings.targetId, targetId), eq(webFindings.findingId, findingId)));
  }
  for (let i = 0; i < inserts.length; i += 200) await db.insert(webFindings).values(inserts.slice(i, i + 200)).onConflictDoNothing();
  const gone = existing.filter((e) => !incoming.has(e.findingId) && e.status !== 'resolved').map((e) => e.findingId);
  for (let i = 0; i < gone.length; i += 200) {
    await db
      .update(webFindings)
      .set({ status: 'resolved', resolvedAt: now })
      .where(and(eq(webFindings.targetId, targetId), inArray(webFindings.findingId, gone.slice(i, i + 200))));
  }
  const [{ n }] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(webFindings)
    .where(and(eq(webFindings.targetId, targetId), eq(webFindings.status, 'open')));
  return { new: created, reopened, resolved: gone.length, open: Number(n) };
}

export interface WebFindingFilter {
  targetId?: string;
  status?: WebFindingStatus[];
  severity?: Severity[];
  limit?: number;
}

export async function listWebFindings(db: DB, f: WebFindingFilter = {}) {
  // 已刪除的目標留著歷史資料，但不出現在清單裡
  const conds: SQL[] = [isNull(webTargets.deletedAt)];
  if (f.targetId) conds.push(eq(webFindings.targetId, f.targetId));
  if (f.status?.length) conds.push(inArray(webFindings.status, f.status));
  if (f.severity?.length) conds.push(inArray(webFindings.severity, f.severity));
  const rows = await db
    .select({ f: webFindings, url: webTargets.url })
    .from(webFindings)
    .innerJoin(webTargets, eq(webTargets.id, webFindings.targetId))
    .where(and(...conds))
    .orderBy(
      sql`case ${webFindings.status} when 'open' then 0 when 'acked' then 1 when 'suppressed' then 2 else 3 end`,
      sql`case ${webFindings.severity} when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end`,
      desc(webFindings.lastSeenAt),
    )
    .limit(Math.min(f.limit ?? 500, 2000));
  return rows.map(({ f: r, url }) => ({
    targetId: r.targetId,
    targetUrl: url,
    findingId: r.findingId,
    scanner: r.scanner,
    rule: r.rule,
    severity: r.severity as Severity,
    title: r.title,
    detail: r.detail,
    recommendation: r.recommendation,
    location: r.location,
    evidence: r.evidence,
    cve: r.cve,
    cwe: r.cwe,
    cvss: r.cvss,
    refs: r.refs,
    tags: r.tags,
    status: r.status as WebFindingStatus,
    firstSeenAt: r.firstSeenAt.toISOString(),
    lastSeenAt: r.lastSeenAt.toISOString(),
    resolvedAt: r.resolvedAt?.toISOString() ?? null,
    ackedBy: r.ackedBy,
    suppressedUntil: r.suppressedUntil?.toISOString() ?? null,
  }));
}
export type WebFindingView = Awaited<ReturnType<typeof listWebFindings>>[number];

/** 管理員標記：已讀（acked）、忽略 N 天（suppressed）、重新開啟。 */
export async function updateWebFindings(
  db: DB,
  targetId: string,
  ids: string[],
  op: { action: 'ack' | 'reopen' } | { action: 'suppress'; days: number; reason?: string },
  actor: string,
  now = new Date(),
): Promise<number> {
  if (!ids.length) return 0;
  const set =
    op.action === 'ack'
      ? { status: 'acked', ackedAt: now, ackedBy: actor }
      : op.action === 'suppress'
        ? { status: 'suppressed', suppressedUntil: new Date(now.getTime() + Math.max(1, Math.min(365, op.days)) * 86_400_000), suppressReason: (op.reason ?? '').slice(0, 300) }
        : { status: 'open', ackedAt: null, ackedBy: null, suppressedUntil: null, suppressReason: null };
  const r = await db
    .update(webFindings)
    .set(set)
    .where(and(eq(webFindings.targetId, targetId), inArray(webFindings.findingId, ids.slice(0, 500))))
    .returning({ id: webFindings.findingId });
  return r.length;
}

export const isFindingStatus = (s: string): s is WebFindingStatus => (WEB_FINDING_STATUSES as readonly string[]).includes(s);
