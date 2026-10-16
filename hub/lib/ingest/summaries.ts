// 報告裡的引擎摘要（summaries.events／summaries.traffic）→ 當機紀錄、資安事件、每台最新摘要。
// 解析寬鬆：欄位不對的單筆略過，不讓整份報告失敗（agent 與 hub 版本可能不同步）。
import crypto from 'node:crypto';
import { sql } from 'drizzle-orm';
import { z } from 'zod';
import { agentSummaries, crashRecords, securityEvents } from '@/drizzle/schema';
import type { DB } from '@/lib/db';

const Str = (max: number) => z.string().max(max);
const Time = z.string().max(64).refine((s) => !Number.isNaN(Date.parse(s)));

export const Crash = z
  .object({
    kind: Str(40),
    time: Time,
    code: Str(64).nullish(),
    name: Str(300).nullish(),
    module: Str(300).nullish(),
    process: Str(300).nullish(),
    params: z.array(Str(64)).max(8).default([]),
    likely_causes: z.array(Str(500)).max(10).default([]),
    remediation: Str(1000).nullish(),
    source: Str(600).default(''),
  })
  .passthrough();

export const SecHit = z
  .object({
    rule: Str(60),
    severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
    count: z.number().int().min(0).max(10_000_000),
    first: Time,
    last: Time,
    source_ip: Str(64).nullish(),
    user: Str(300).nullish(),
    detail: Str(1000).default(''),
    intel: z.array(z.record(z.string(), z.unknown())).max(20).default([]),
  })
  .passthrough();

export type CrashT = z.infer<typeof Crash>;
export type SecHitT = z.infer<typeof SecHit>;

function key(parts: (string | null | undefined)[]): string {
  return crypto.createHash('sha256').update(parts.map((p) => p ?? '').join('|')).digest('hex').slice(0, 32);
}

/** 只取能解析的項目。 */
function pick<T>(schema: z.ZodType<T>, list: unknown, max: number): T[] {
  if (!Array.isArray(list)) return [];
  const out: T[] = [];
  for (const x of list.slice(0, max)) {
    const r = schema.safeParse(x);
    if (r.success) out.push(r.data);
  }
  return out;
}

export interface SummaryResult {
  crashes: number;
  security: number;
}

export async function applySummaries(db: DB, agentId: string, summaries: Record<string, unknown>, at: Date): Promise<SummaryResult> {
  const res: SummaryResult = { crashes: 0, security: 0 };
  for (const kind of ['events', 'traffic'] as const) {
    const s = summaries[kind];
    if (s && typeof s === 'object' && !Array.isArray(s)) {
      await db
        .insert(agentSummaries)
        .values({ agentId, kind, at, summary: s as Record<string, unknown> })
        .onConflictDoUpdate({ target: [agentSummaries.agentId, agentSummaries.kind], set: { at, summary: s as Record<string, unknown> } });
    }
  }
  const ev = summaries.events as Record<string, unknown> | undefined;
  if (!ev || typeof ev !== 'object') return res;

  const crashes = pick(Crash, ev.crashes, 200);
  if (crashes.length) {
    const rows = crashes.map((c) => ({
      agentId,
      time: new Date(c.time),
      kind: c.kind,
      code: c.code ?? null,
      name: c.name ?? null,
      module: c.module ?? null,
      process: c.process ?? null,
      details: { params: c.params, likely_causes: c.likely_causes, remediation: c.remediation ?? null, source: c.source },
      dedupeKey: key([c.kind, c.time, c.code, c.name, c.module, c.process]),
    }));
    const inserted = await db.insert(crashRecords).values(rows).onConflictDoNothing().returning({ id: crashRecords.id });
    res.crashes = inserted.length;
  }

  // 摘要是滾動的 N 天視窗：同一列以最新一份的次數為準，時間取聯集。
  for (const h of pick(SecHit, ev.security, 100)) {
    const row = {
      agentId,
      rule: h.rule,
      severity: h.severity,
      count: h.count,
      firstAt: new Date(h.first),
      lastAt: new Date(h.last),
      sourceIp: h.source_ip ?? null,
      userName: h.user ?? null,
      detail: h.detail,
      intel: h.intel,
      dedupeKey: key([h.rule, h.source_ip, h.user, h.detail]),
      updatedAt: at,
    };
    await db
      .insert(securityEvents)
      .values(row)
      .onConflictDoUpdate({
        target: [securityEvents.agentId, securityEvents.dedupeKey],
        set: {
          severity: row.severity,
          count: sql`greatest(${securityEvents.count}, ${row.count})`,
          firstAt: sql`least(${securityEvents.firstAt}, ${row.firstAt.toISOString()}::timestamptz)`,
          lastAt: sql`greatest(${securityEvents.lastAt}, ${row.lastAt.toISOString()}::timestamptz)`,
          intel: row.intel,
          updatedAt: at,
        },
      });
    res.security += 1;
  }
  return res;
}
