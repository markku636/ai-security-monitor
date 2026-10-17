// 攻擊手法總覽（/mitre）：依規則彙總待處理的問題，再透過對應表算出每個 MITRE 技術、每個法規控制項的問題數與主機數。
import { and, count, gte, inArray, isNull, sql, type SQL } from 'drizzle-orm';
import { eq } from 'drizzle-orm';
import { agents, findings } from '@/drizzle/schema';
import { mapRule } from '@/lib/attack/mapping';
import { getDb } from '@/lib/db';

export const ATTACK_WINDOWS = ['7', '30', 'all'] as const;
export type AttackWindow = (typeof ATTACK_WINDOWS)[number];

export interface AttackCell {
  findings: number;
  hosts: number;
  rules: string[];
}

export interface AttackSummary {
  techniques: Record<string, AttackCell>;
  controls: Record<string, AttackCell>;
  /** 範圍內待處理、但對應表沒有涵蓋的問題數（效能告警、當機等）。 */
  unmapped: number;
  total: number;
}

/** 待處理（未處理＋已確認）的問題，依「最後看到」篩時間範圍。 */
export async function attackSummary(window: AttackWindow = '30', agentId?: string): Promise<AttackSummary> {
  const conds: SQL[] = [isNull(agents.deletedAt), inArray(findings.status, ['open', 'acked'])];
  if (window !== 'all') conds.push(gte(findings.lastSeenAt, sql`now() - (${Number(window)} * interval '1 day')`));
  if (agentId) conds.push(eq(findings.agentId, agentId));
  const rows = await getDb()
    .select({ rule: findings.rule, n: count(), hosts: sql<string[]>`array_agg(distinct ${findings.agentId})` })
    .from(findings)
    .innerJoin(agents, eq(agents.id, findings.agentId))
    .where(and(...conds))
    .groupBy(findings.rule);
  const tech = new Map<string, { findings: number; hosts: Set<string>; rules: string[] }>();
  const ctrl = new Map<string, { findings: number; hosts: Set<string>; rules: string[] }>();
  let unmapped = 0;
  let total = 0;
  const add = (m: typeof tech, key: string, rule: string, n: number, hosts: string[]) => {
    const cur = m.get(key) ?? { findings: 0, hosts: new Set<string>(), rules: [] };
    cur.findings += n;
    for (const h of hosts) cur.hosts.add(h);
    if (!cur.rules.includes(rule)) cur.rules.push(rule);
    m.set(key, cur);
  };
  for (const r of rows) {
    const n = Number(r.n);
    const hosts = (r.hosts ?? []).filter(Boolean);
    total += n;
    const m = mapRule(r.rule);
    if (!m.mitre.length && !m.compliance.length) unmapped += n;
    // 子技術也算進上層技術（T1003.001 → T1003），矩陣上兩格都會亮
    const ids = new Set(m.mitre.flatMap((id) => (id.includes('.') ? [id, id.split('.')[0]] : [id])));
    for (const id of ids) add(tech, id, r.rule, n, hosts);
    for (const c of m.compliance) add(ctrl, c, r.rule, n, hosts);
  }
  const out = (m: typeof tech) =>
    Object.fromEntries([...m].map(([k, v]) => [k, { findings: v.findings, hosts: v.hosts.size, rules: v.rules.sort() }]));
  return { techniques: out(tech), controls: out(ctrl), unmapped, total };
}
