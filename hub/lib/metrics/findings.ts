// 效能門檻 → 待處理問題（只在主機開啟效能蒐集時）：磁碟用量 ≥ 90%、CPU 連續 15 分鐘 ≥ 90%，都是「低」。
// 條件不成立就自動標為已解決；主機關掉效能蒐集時一併解決（沒有資料就不再判斷）。
import crypto from 'node:crypto';
import { and, desc, eq, gte, inArray, notInArray } from 'drizzle-orm';
import { agents, findings, hostMetrics } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { recountAgent } from '@/lib/queries/findings';

export const METRICS_SCANNER = 'metrics';
export const RULE_DISK = 'metrics.disk_full';
export const RULE_CPU = 'metrics.cpu_sustained';
export const DISK_THRESHOLD = 90;
export const CPU_THRESHOLD = 90;
/** CPU 要連續多久都超過門檻。 */
export const CPU_WINDOW_MS = 15 * 60_000;
/** 已開的 CPU 問題要降到多少以下（最近 5 分鐘平均）才算解決，避免一直開開關關。 */
export const CPU_CLEAR = 80;
const REPORT_ID = 'metrics';

const hash = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

interface Candidate {
  findingId: string;
  rule: string;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  indicator: string | null;
}

/** 依最近的原始樣本判斷；回傳目前成立的問題與（CPU）是否可以解除。純函式，方便測試。 */
export function judge(
  rows: { at: Date; intervalS: number; cpuPct: number | null; disks: { mount: string; used: number; total: number }[] | null }[],
): { open: Candidate[]; cpuClear: boolean } {
  const sorted = [...rows].sort((a, b) => a.at.getTime() - b.at.getTime());
  const latest = sorted[sorted.length - 1];
  const open: Candidate[] = [];
  if (!latest) return { open, cpuClear: true };
  for (const d of latest.disks ?? []) {
    if (d.total <= 0) continue;
    const pct = (d.used / d.total) * 100;
    if (pct < DISK_THRESHOLD) continue;
    const p = Math.round(pct);
    open.push({
      findingId: `m_disk_${hash(d.mount).slice(0, 16)}`,
      rule: RULE_DISK,
      title: `磁碟 ${d.mount} 已用 ${p}%`,
      detail: `${d.mount} 已用 ${(d.used / 1024 ** 3).toFixed(1)} GB／${(d.total / 1024 ** 3).toFixed(1)} GB（${p}%）。磁碟太滿會讓更新失敗、記錄寫不進去，系統也會變慢。`,
      evidence: { type: 'metric', metric: 'disk_used_pct', mount: d.mount, value: p, threshold: DISK_THRESHOLD, used: d.used, total: d.total },
      recommendation: '清掉不需要的檔案（下載、暫存、舊的備份與記錄），或把資料搬到其他磁碟；Windows 可用「磁碟清理」或「儲存空間感知」。',
      indicator: d.mount,
    });
  }
  const end = latest.at.getTime();
  const win = sorted.filter((r) => r.cpuPct != null && r.at.getTime() >= end - CPU_WINDOW_MS);
  const covered = win.length ? end - win[0].at.getTime() + win[0].intervalS * 1000 : 0;
  if (win.length >= 3 && covered >= CPU_WINDOW_MS - 60_000 && win.every((r) => (r.cpuPct ?? 0) >= CPU_THRESHOLD)) {
    const avg = Math.round(win.reduce((a, r) => a + (r.cpuPct ?? 0), 0) / win.length);
    open.push({
      findingId: 'm_cpu_sustained',
      rule: RULE_CPU,
      title: `CPU 連續 15 分鐘超過 ${CPU_THRESHOLD}%（平均 ${avg}%）`,
      detail: `最近 15 分鐘的每個樣本 CPU 使用率都在 ${CPU_THRESHOLD}% 以上。可能是正常的大量工作，也可能是程式卡住、挖礦程式或惡意軟體。`,
      evidence: { type: 'metric', metric: 'cpu_pct', value: avg, threshold: CPU_THRESHOLD, window_min: 15 },
      recommendation: '在 Hub 主機頁的「效能」分頁看是哪個程式最吃 CPU；不認得的程式先查它的路徑與簽章。',
      indicator: null,
    });
  }
  const last5 = sorted.filter((r) => r.cpuPct != null && r.at.getTime() >= end - 5 * 60_000);
  const cpuClear = !last5.length || last5.reduce((a, r) => a + (r.cpuPct ?? 0), 0) / last5.length < CPU_CLEAR;
  return { open, cpuClear };
}

export async function evaluateMetricFindings(db: DB, agentId: string, performance: boolean, now = new Date()): Promise<{ opened: number; resolved: number }> {
  let opened = 0;
  let resolved = 0;
  const existing = await db
    .select({ findingId: findings.findingId, rule: findings.rule, status: findings.status })
    .from(findings)
    .where(and(eq(findings.agentId, agentId), eq(findings.scanner, METRICS_SCANNER)));
  let cands: Candidate[] = [];
  let cpuClear = true;
  if (performance) {
    const rows = await db
      .select({ at: hostMetrics.at, intervalS: hostMetrics.intervalS, cpuPct: hostMetrics.cpuPct, disks: hostMetrics.disks })
      .from(hostMetrics)
      .where(and(eq(hostMetrics.agentId, agentId), eq(hostMetrics.perf, true), gte(hostMetrics.at, new Date(now.getTime() - 60 * 60_000))))
      .orderBy(desc(hostMetrics.at))
      .limit(120);
    ({ open: cands, cpuClear } = judge(rows));
  }
  const byId = new Map(existing.map((e) => [e.findingId, e]));
  for (const c of cands) {
    const ex = byId.get(c.findingId);
    const common = {
      scanner: METRICS_SCANNER,
      rule: c.rule,
      severity: 'low',
      title: c.title,
      detail: c.detail,
      evidence: c.evidence,
      recommendation: c.recommendation,
      tags: ['performance'],
      lastSeenAt: now,
      lastReportId: REPORT_ID,
      contentHash: hash(c.rule + c.indicator).slice(0, 32),
      indicator: c.indicator,
    };
    if (!ex) {
      await db.insert(findings).values({ agentId, findingId: c.findingId, ...common, status: 'open', firstSeenAt: now, firstReportId: REPORT_ID });
      opened++;
    } else {
      await db
        .update(findings)
        .set({ ...common, ...(ex.status === 'resolved' ? { status: 'open', resolvedAt: null } : {}) })
        .where(and(eq(findings.agentId, agentId), eq(findings.findingId, c.findingId)));
      if (ex.status === 'resolved') opened++;
    }
  }
  // 不再成立的 → 已解決（CPU 要降到 CPU_CLEAR 以下才解除）
  const keep = cands.map((c) => c.findingId);
  if (!cpuClear && byId.has('m_cpu_sustained')) keep.push('m_cpu_sustained');
  const toResolve = existing.filter((e) => (e.status === 'open' || e.status === 'acked') && !keep.includes(e.findingId)).map((e) => e.findingId);
  if (toResolve.length) {
    const r = await db
      .update(findings)
      .set({ status: 'resolved', resolvedAt: now })
      .where(and(eq(findings.agentId, agentId), eq(findings.scanner, METRICS_SCANNER), inArray(findings.findingId, toResolve), notInArray(findings.status, ['resolved', 'suppressed'])))
      .returning({ id: findings.findingId });
    resolved = r.length;
  }
  if (opened || resolved || cands.length) {
    const { sevCounts, open } = await recountAgent(db, agentId);
    await db.update(agents).set({ sevCounts, openFindings: open }).where(eq(agents.id, agentId));
  }
  return { opened, resolved };
}
