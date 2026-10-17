// 漏洞與硬化：agent 報告裡的 summaries.vuln／summaries.hardening（每台最新一份，存在 agent_summaries）。
// 摘要是 agent 送來的 JSON，這裡用寬鬆的 zod 解析，欄位缺了就給預設值，不讓單一壞資料拖垮整頁。
import { and, eq, isNull } from 'drizzle-orm';
import { z } from 'zod';
import { agentSummaries, agents } from '@/drizzle/schema';
import { getDb } from '@/lib/db';

const str = z.string().catch('');
const optStr = z.string().nullish().catch(null);
const n = z.number().catch(0);
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
const sev = z.enum(SEVERITIES).catch('info');

const OsSupport = z
  .object({ product: str, eol: optStr, status: z.enum(['supported', 'ending_soon', 'eol', 'unknown']).catch('unknown'), days_left: z.number().nullish().catch(null), note: optStr })
  .nullish()
  .catch(null);

const AppHit = z.object({
  rule_id: str,
  app: str,
  installed_name: str,
  installed: str,
  fixed: str,
  cves: z.array(z.string()).catch([]),
  kev: z.array(z.string()).catch([]),
  severity: sev,
  eol: z.boolean().catch(false),
  summary: str,
  fix: str,
  reference: str,
});

const OsvPackage = z.object({
  name: str,
  version: str,
  ids: z.array(z.string()).catch([]),
  cves: z.array(z.string()).catch([]),
  kev: z.array(z.string()).catch([]),
  severity: sev,
  summary: str,
});

export const VulnSummary = z.object({
  os: z.object({ family: str, name: str, version: str, build: z.number().nullish().catch(null) }).catch({ family: '', name: '', version: '', build: null }),
  support: OsSupport,
  last_patch: z.object({ date: str, id: str, days: n }).nullish().catch(null),
  pending_updates: z.object({ total: n, security: n }).nullish().catch(null),
  packages: n,
  by_ecosystem: z.record(z.string(), z.number()).catch({}),
  app_hits: z.array(AppHit).catch([]),
  osv: z.object({ ecosystem: str, queried: n, packages: z.array(OsvPackage).catch([]) }).nullish().catch(null),
  kev_count: n,
  notes: z.array(z.string()).catch([]),
});
export type VulnSummary = z.infer<typeof VulnSummary>;
export type AppHit = z.infer<typeof AppHit>;

const Outcome = z.object({
  id: str,
  category: str,
  severity: sev,
  title: str,
  result: z.enum(['pass', 'fail', 'not_applicable', 'error']).catch('error'),
  observed: str,
  expected: str,
  remediation: str,
  rationale: str,
  references: z.array(z.string()).catch([]),
  note: optStr,
});

export const HardeningSummary = z.object({
  os_family: str,
  pass: n,
  fail: n,
  na: n,
  error: n,
  score: z.number().nullish().catch(null),
  needs_admin: z.array(z.string()).catch([]),
  results: z.array(Outcome).catch([]),
});
export type HardeningSummary = z.infer<typeof HardeningSummary>;
export type Outcome = z.infer<typeof Outcome>;

type Kind = 'vuln' | 'hardening';

async function summaries(kind: Kind, agentId?: string) {
  const conds = [eq(agentSummaries.kind, kind), isNull(agents.deletedAt)];
  if (agentId) conds.push(eq(agentSummaries.agentId, agentId));
  return getDb()
    .select({ agentId: agentSummaries.agentId, hostname: agents.hostname, osFamily: agents.osFamily, at: agentSummaries.at, summary: agentSummaries.summary })
    .from(agentSummaries)
    .innerJoin(agents, eq(agents.id, agentSummaries.agentId))
    .where(and(...conds))
    .orderBy(agents.hostname);
}

export async function agentVuln(agentId: string): Promise<{ at: Date; summary: VulnSummary } | null> {
  const [row] = await summaries('vuln', agentId);
  return row ? { at: row.at, summary: VulnSummary.parse(row.summary) } : null;
}

export async function agentHardening(agentId: string): Promise<{ at: Date; summary: HardeningSummary } | null> {
  const [row] = await summaries('hardening', agentId);
  return row ? { at: row.at, summary: HardeningSummary.parse(row.summary) } : null;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export interface HostRef {
  agentId: string;
  hostname: string;
}

/** 車隊的漏洞概況：作業系統支援、更新、已知漏洞軟體（依規則彙總）、OSV。 */
export async function vulnOverview(agentId?: string) {
  const rows = (await summaries('vuln')).filter((r) => !agentId || r.agentId === agentId).map((r) => ({ ...r, s: VulnSummary.parse(r.summary) }));
  const os = rows
    .map((r) => ({ agentId: r.agentId, hostname: r.hostname, name: [r.s.os.name, r.s.os.version].filter(Boolean).join(' '), support: r.s.support, at: r.at }))
    .sort((a, b) => statusRank(b.support?.status) - statusRank(a.support?.status) || a.hostname.localeCompare(b.hostname));
  const patches = rows
    .filter((r) => r.s.last_patch || r.s.pending_updates)
    .map((r) => ({ agentId: r.agentId, hostname: r.hostname, lastPatch: r.s.last_patch ?? null, pending: r.s.pending_updates ?? null }))
    .sort((a, b) => (b.lastPatch?.days ?? -1) - (a.lastPatch?.days ?? -1) || (b.pending?.security ?? 0) - (a.pending?.security ?? 0));
  const byRule = new Map<string, { hit: AppHit; hosts: (HostRef & { installed: string })[] }>();
  for (const r of rows) {
    for (const h of r.s.app_hits) {
      const e = byRule.get(h.rule_id) ?? { hit: h, hosts: [] };
      if (SEV_RANK[h.severity] > SEV_RANK[e.hit.severity]) e.hit = h;
      e.hosts.push({ agentId: r.agentId, hostname: r.hostname, installed: h.installed });
      byRule.set(h.rule_id, e);
    }
  }
  const apps = [...byRule.values()].sort((a, b) => SEV_RANK[b.hit.severity] - SEV_RANK[a.hit.severity] || b.hosts.length - a.hosts.length);
  const osv = rows
    .filter((r) => r.s.osv)
    .map((r) => {
      const pk = r.s.osv!.packages;
      return {
        agentId: r.agentId,
        hostname: r.hostname,
        ecosystem: r.s.osv!.ecosystem,
        queried: r.s.osv!.queried,
        packages: pk.length,
        critical: pk.filter((p) => p.severity === 'critical').length,
        high: pk.filter((p) => p.severity === 'high').length,
        kev: pk.reduce((a, p) => a + p.kev.length, 0),
      };
    })
    .sort((a, b) => b.kev - a.kev || b.critical - a.critical || b.packages - a.packages);
  return {
    hosts: rows.length,
    unsupported: os.filter((o) => o.support?.status === 'eol').length,
    endingSoon: os.filter((o) => o.support?.status === 'ending_soon').length,
    kevHosts: rows.filter((r) => r.s.kev_count > 0).length,
    stalePatches: patches.filter((p) => (p.lastPatch?.days ?? 0) > 45 || (p.pending?.security ?? 0) > 0).length,
    os,
    patches,
    apps,
    osv,
  };
}

function statusRank(s: string | undefined) {
  return s === 'eol' ? 3 : s === 'ending_soon' ? 2 : s === 'unknown' ? 1 : 0;
}

/** 車隊的硬化概況：每台分數、最常沒通過的檢查。 */
export async function hardeningOverview(agentId?: string) {
  const rows = (await summaries('hardening')).filter((r) => !agentId || r.agentId === agentId).map((r) => ({ ...r, s: HardeningSummary.parse(r.summary) }));
  const hosts = rows
    .map((r) => ({ agentId: r.agentId, hostname: r.hostname, osFamily: r.s.os_family || r.osFamily, at: r.at, score: r.s.score ?? null, pass: r.s.pass, fail: r.s.fail, na: r.s.na, needsAdmin: r.s.needs_admin.length }))
    .sort((a, b) => (a.score ?? 101) - (b.score ?? 101) || a.hostname.localeCompare(b.hostname));
  const failed = new Map<string, { check: Outcome; hosts: HostRef[]; checked: number }>();
  for (const r of rows) {
    for (const o of r.s.results) {
      if (o.result !== 'pass' && o.result !== 'fail') continue;
      const e = failed.get(o.id) ?? { check: o, hosts: [], checked: 0 };
      e.checked += 1;
      if (o.result === 'fail') e.hosts.push({ agentId: r.agentId, hostname: r.hostname });
      failed.set(o.id, e);
    }
  }
  const topFailed = [...failed.values()]
    .filter((e) => e.hosts.length)
    .sort((a, b) => b.hosts.length - a.hosts.length || SEV_RANK[b.check.severity] - SEV_RANK[a.check.severity]);
  const scored = hosts.filter((h) => h.score != null);
  return {
    hosts,
    average: scored.length ? Math.round(scored.reduce((a, h) => a + (h.score ?? 0), 0) / scored.length) : null,
    topFailed,
  };
}
