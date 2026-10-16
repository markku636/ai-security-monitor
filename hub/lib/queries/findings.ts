// 發現（finding）查詢與批次處理：確認、暫停、重新開啟。
import { and, count, desc, eq, ilike, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import { agents, findings, type SevCounts } from '@/drizzle/schema';
import { getDb, type DB } from '@/lib/db';
import { likePattern } from './connections';
import { clampInt, listParam, strParam, type Params } from './params';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const STATUSES = ['open', 'acked', 'suppressed', 'resolved'] as const;
export const SCANNERS = ['connections', 'intel', 'ports', 'firewall', 'vuln', 'hardening', 'files', 'traffic', 'events'] as const;
export type Severity = (typeof SEVERITIES)[number];
export type FindingStatus = (typeof STATUSES)[number];

export interface FindingFilter {
  agentId?: string;
  status: FindingStatus[];
  severity: Severity[];
  scanner: string[];
  q?: string;
  limit: number;
  offset: number;
}

export function parseFindingFilter(p: Params): FindingFilter {
  const status = listParam(p, 'status', STATUSES);
  return {
    agentId: strParam(p, 'agent_id', 64),
    // 沒指定就看「待處理」：未處理＋已確認。
    status: status.length ? status : ['open', 'acked'],
    severity: listParam(p, 'severity', SEVERITIES),
    scanner: listParam(p, 'scanner', SCANNERS),
    q: strParam(p, 'q', 100),
    limit: clampInt(p, 'limit', 100, 1, 200),
    offset: clampInt(p, 'offset', 0, 0, 100_000),
  };
}

const SEV_ORDER = sql`case ${findings.severity} when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end`;

function where(f: FindingFilter, skip: { severity?: boolean; status?: boolean } = {}): SQL {
  const conds: SQL[] = [isNull(agents.deletedAt)];
  if (f.agentId) conds.push(eq(findings.agentId, f.agentId));
  if (!skip.status && f.status.length) conds.push(inArray(findings.status, f.status));
  if (!skip.severity && f.severity.length) conds.push(inArray(findings.severity, f.severity));
  if (f.scanner.length) conds.push(inArray(findings.scanner, f.scanner));
  if (f.q) {
    const like = likePattern(f.q);
    conds.push(
      or(ilike(findings.title, like), ilike(findings.indicator, like), ilike(findings.rule, like), ilike(agents.hostname, like))!,
    );
  }
  return and(...conds)!;
}

export async function listFindings(f: FindingFilter) {
  const db = getDb();
  const facet = (k: typeof findings.severity | typeof findings.status, skip: { severity?: boolean; status?: boolean }) =>
    db
      .select({ k, n: count() })
      .from(findings)
      .innerJoin(agents, eq(agents.id, findings.agentId))
      .where(where(f, skip))
      .groupBy(k);
  const [items, total, bySeverity, byStatus] = await Promise.all([
    db
      .select({
        agentId: findings.agentId,
        findingId: findings.findingId,
        hostname: agents.hostname,
        scanner: findings.scanner,
        rule: findings.rule,
        severity: findings.severity,
        title: findings.title,
        detail: findings.detail,
        recommendation: findings.recommendation,
        intelHits: findings.intelHits,
        tags: findings.tags,
        status: findings.status,
        indicator: findings.indicator,
        firstSeenAt: findings.firstSeenAt,
        lastSeenAt: findings.lastSeenAt,
        ackedBy: findings.ackedBy,
        suppressedUntil: findings.suppressedUntil,
        allowlistedBy: findings.allowlistedBy,
      })
      .from(findings)
      .innerJoin(agents, eq(agents.id, findings.agentId))
      .where(where(f))
      .orderBy(SEV_ORDER, desc(findings.lastSeenAt), findings.findingId)
      .limit(f.limit)
      .offset(f.offset),
    db
      .select({ n: count() })
      .from(findings)
      .innerJoin(agents, eq(agents.id, findings.agentId))
      .where(where(f)),
    facet(findings.severity, { severity: true }),
    facet(findings.status, { status: true }),
  ]);
  const toMap = (rows: { k: string; n: number }[]) => Object.fromEntries(rows.map((r) => [r.k, Number(r.n)])) as Record<string, number>;
  return {
    items: items.map((r) => ({ ...r, intelHits: (Array.isArray(r.intelHits) ? r.intelHits : []) as IntelHitJson[] })),
    total: Number(total[0]?.n ?? 0),
    facets: { severity: toMap(bySeverity), status: toMap(byStatus) },
  };
}

export type FindingRow = Awaited<ReturnType<typeof listFindings>>['items'][number];

export interface IntelHitJson {
  feed_id: string;
  name: string;
  vendor: string;
  confidence: number;
  license: string;
  license_url?: string;
  source_url: string;
  fetched_at?: string;
  matched?: string;
}

export async function getFinding(agentId: string, findingId: string) {
  const rows = await getDb()
    .select()
    .from(findings)
    .where(and(eq(findings.agentId, agentId), eq(findings.findingId, findingId)))
    .limit(1);
  return rows[0] ?? null;
}

/** 依目前「未處理」的 finding 重算 agent 的嚴重度計數。 */
export async function recountAgent(db: DB, agentId: string): Promise<{ sevCounts: SevCounts; open: number }> {
  const sev = await db
    .select({ severity: findings.severity, n: sql<number>`count(*)::int` })
    .from(findings)
    .where(and(eq(findings.agentId, agentId), eq(findings.status, 'open')))
    .groupBy(findings.severity);
  const sevCounts: SevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const s of sev) if (s.severity in sevCounts) sevCounts[s.severity as keyof SevCounts] = Number(s.n);
  const open = Object.values(sevCounts).reduce((a, b) => a + b, 0);
  return { sevCounts, open };
}

export type BulkAction = 'ack' | 'suppress' | 'reopen';
export interface FindingKey {
  agent_id: string;
  finding_id: string;
}

/**
 * 批次處理：ack（未處理→已確認）、suppress（未處理／已確認→暫停 N 天）、reopen（已確認／暫停→未處理）。
 * 已解決的 finding 由 agent 的下一份報告決定，這裡不動。回傳實際變更的筆數。
 */
export async function bulkUpdateFindings(
  keys: FindingKey[],
  action: BulkAction,
  opts: { actor: string; days?: number; reason?: string },
): Promise<{ changed: number; agents: string[] }> {
  const db = getDb();
  const now = new Date();
  return db.transaction(async (tx) => {
    const t = tx as unknown as DB;
    let changed = 0;
    const touched = new Set<string>();
    const byAgent = new Map<string, string[]>();
    for (const k of keys) byAgent.set(k.agent_id, [...(byAgent.get(k.agent_id) ?? []), k.finding_id]);
    for (const [agentId, ids] of byAgent) {
      const match = and(eq(findings.agentId, agentId), inArray(findings.findingId, ids));
      let res: { id: string }[];
      if (action === 'ack') {
        res = await t
          .update(findings)
          .set({ status: 'acked', ackedAt: now, ackedBy: opts.actor })
          .where(and(match, eq(findings.status, 'open')))
          .returning({ id: findings.findingId });
      } else if (action === 'suppress') {
        const days = Math.min(Math.max(opts.days ?? 30, 1), 365);
        res = await t
          .update(findings)
          .set({
            status: 'suppressed',
            suppressedUntil: new Date(now.getTime() + days * 86_400_000),
            suppressReason: opts.reason?.slice(0, 500) ?? null,
            ackedBy: opts.actor,
          })
          .where(and(match, inArray(findings.status, ['open', 'acked'])))
          .returning({ id: findings.findingId });
      } else {
        res = await t
          .update(findings)
          .set({ status: 'open', ackedAt: null, ackedBy: null, suppressedUntil: null, suppressReason: null })
          .where(and(match, inArray(findings.status, ['acked', 'suppressed'])))
          .returning({ id: findings.findingId });
      }
      if (res.length) {
        changed += res.length;
        touched.add(agentId);
        const { sevCounts, open } = await recountAgent(t, agentId);
        await t.update(agents).set({ sevCounts, openFindings: open }).where(eq(agents.id, agentId));
      }
    }
    return { changed, agents: [...touched] };
  });
}

/** 給 client 元件的可序列化形狀（日期轉 ISO）。 */
export function toFindingView(r: FindingRow) {
  return {
    agentId: r.agentId,
    findingId: r.findingId,
    hostname: r.hostname,
    scanner: r.scanner,
    rule: r.rule,
    severity: r.severity,
    title: r.title,
    detail: r.detail,
    recommendation: r.recommendation,
    status: r.status,
    indicator: r.indicator,
    firstSeenAt: r.firstSeenAt.toISOString(),
    lastSeenAt: r.lastSeenAt.toISOString(),
    ackedBy: r.ackedBy,
    suppressedUntil: r.suppressedUntil ? r.suppressedUntil.toISOString() : null,
    allowlistedBy: r.allowlistedBy,
    tags: r.tags ?? [],
    intelHits: r.intelHits,
  };
}
