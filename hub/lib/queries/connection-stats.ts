// 連線統計（AI 分析用的 MCP 工具 connection_stats）：直接在資料庫分組計數，AI 不用自己數。
import { and, count, desc, eq, inArray, isNull, sql, type SQL } from 'drizzle-orm';
import { agents, connections } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

const TOP = 15;

export interface StatsFilter {
  agentId?: string;
  direction?: string[];
  verdict?: string[];
}

export async function connectionStats(f: StatsFilter = {}) {
  const db = getDb();
  const conds: SQL[] = [isNull(agents.deletedAt)];
  if (f.agentId) conds.push(eq(connections.agentId, f.agentId));
  if (f.direction?.length) conds.push(inArray(connections.direction, f.direction));
  if (f.verdict?.length) conds.push(inArray(connections.verdict, f.verdict));
  const where = and(...conds);
  const group = async (key: SQL, limit = TOP) => {
    const rows = await db
      .select({ key: sql<string | null>`${key}`, n: count() })
      .from(connections)
      .innerJoin(agents, eq(agents.id, connections.agentId))
      .where(where)
      .groupBy(sql`1`)
      .orderBy(desc(count()), sql`1`)
      .limit(limit + 1);
    return {
      groups: rows.slice(0, limit).map((r) => ({ key: r.key ?? '?', count: Number(r.n) })),
      more: rows.length > limit,
    };
  };
  const [[total], byVerdict, byDirection, byState, byProto, byProcess, byCountry, byPort, byIp, byHost] = await Promise.all([
    db.select({ n: count() }).from(connections).innerJoin(agents, eq(agents.id, connections.agentId)).where(where),
    group(sql`${connections.verdict}`),
    group(sql`${connections.direction}`),
    group(sql`${connections.state}`),
    group(sql`${connections.proto}`),
    group(sql`${connections.processName}`),
    group(sql`${connections.country}`),
    group(sql`${connections.remotePort}::text`),
    group(sql`${connections.remoteIp}`),
    group(sql`${agents.hostname}`),
  ]);
  return {
    total: Number(total?.n ?? 0),
    by_verdict: byVerdict,
    by_direction: byDirection,
    by_state: byState,
    by_proto: byProto,
    by_process: byProcess,
    by_country: byCountry,
    by_remote_port: byPort,
    by_remote_ip: byIp,
    by_host: byHost,
  };
}
