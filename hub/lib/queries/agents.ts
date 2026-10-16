// 讀取查詢：頁面、API、（之後的）MCP 工具共用同一份 SQL，確保「AI 看到的＝畫面顯示的」。
import { and, count, desc, eq, isNull, sql } from 'drizzle-orm';
import { agents, connections, reports, type Scores, type SevCounts } from '@/drizzle/schema';
import { getDb } from '@/lib/db';
import { env } from '@/lib/env';

export type AgentStatus = 'online' | 'stale' | 'offline';

export function agentStatus(lastSeen: Date, now = Date.now()): AgentStatus {
  const age = now - lastSeen.getTime();
  const e = env();
  const fresh = Math.max(15 * 60_000, e.snapshotMinIntervalMs * 3);
  if (age <= fresh) return 'online';
  if (age <= Math.max(e.staleAfterMs, fresh) * 48) return 'stale';
  return 'offline';
}

export async function listAgents() {
  const rows = await getDb()
    .select()
    .from(agents)
    .where(isNull(agents.deletedAt))
    .orderBy(desc(agents.lastSeenAt))
    .limit(1000);
  const now = Date.now();
  return rows.map((a) => ({ ...a, status: agentStatus(a.lastSeenAt, now) }));
}

export interface FleetSummary {
  agents: { total: number; online: number; stale: number; offline: number };
  severities: SevCounts;
  connections: { dangerous: number; suspicious: number };
}

export async function fleetSummary(): Promise<FleetSummary> {
  const db = getDb();
  const list = await listAgents();
  const severities: SevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of list) {
    for (const k of Object.keys(severities) as (keyof SevCounts)[]) severities[k] += a.sevCounts?.[k] ?? 0;
  }
  const verdicts = await db
    .select({ verdict: connections.verdict, n: count() })
    .from(connections)
    .innerJoin(agents, and(eq(agents.id, connections.agentId), isNull(agents.deletedAt)))
    .where(sql`${connections.verdict} in ('dangerous', 'suspicious')`)
    .groupBy(connections.verdict);
  const v = Object.fromEntries(verdicts.map((x) => [x.verdict, Number(x.n)]));
  return {
    agents: {
      total: list.length,
      online: list.filter((a) => a.status === 'online').length,
      stale: list.filter((a) => a.status === 'stale').length,
      offline: list.filter((a) => a.status === 'offline').length,
    },
    severities,
    connections: { dangerous: v.dangerous ?? 0, suspicious: v.suspicious ?? 0 },
  };
}

export async function getAgent(id: string) {
  const rows = await getDb()
    .select()
    .from(agents)
    .where(and(eq(agents.id, id), isNull(agents.deletedAt)))
    .limit(1);
  const a = rows[0];
  return a ? { ...a, status: agentStatus(a.lastSeenAt) } : null;
}

/** 某 agent 最近的報告（不含原始內容）。 */
export async function agentReports(id: string, limit = 30) {
  return getDb()
    .select({
      id: reports.id,
      startedAt: reports.startedAt,
      finishedAt: reports.finishedAt,
      receivedAt: reports.receivedAt,
      scannersRun: reports.scannersRun,
      score: reports.score,
      findingsCount: reports.findingsCount,
      newCount: reports.newCount,
      resolvedCount: reports.resolvedCount,
      partial: reports.partial,
      payloadBytes: reports.payloadBytes,
    })
    .from(reports)
    .where(eq(reports.agentId, id))
    .orderBy(desc(reports.finishedAt))
    .limit(Math.min(limit, 200));
}

/** 車隊平均分數（有分數的 agent）。 */
export function averageScore(list: { score: Scores | null }[]): Scores | null {
  const scored = list.filter((a): a is { score: Scores } => !!a.score);
  if (!scored.length) return null;
  const keys: (keyof Scores)[] = ['overall', 'connections', 'exposure', 'vulns', 'hardening'];
  return Object.fromEntries(
    keys.map((k) => [k, Math.round(scored.reduce((s, a) => s + (a.score[k] ?? 0), 0) / scored.length)]),
  ) as unknown as Scores;
}
