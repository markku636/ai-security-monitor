// 清除歷史：AI 分析紀錄（＋AI 程式自己留的對話紀錄）、連線歷史（可疑 IP 排名的累計）、外部情資查詢快取。
// 都是管理員手動觸發或保留期限自動清；IP 備註、主機、問題、稽核紀錄不在這裡清。
import fs from 'node:fs';
import path from 'node:path';
import { and, count, eq, lt, min, ne, type SQL } from 'drizzle-orm';
import { aiAnalyses, destinations, ipReputation } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { env } from '@/lib/env';

export const HISTORY_KINDS = ['ai', 'connections', 'ipintel'] as const;
export type HistoryKind = (typeof HISTORY_KINDS)[number];

export interface HistoryStat {
  count: number;
  oldest: string | null;
  /** 自動清除的保留天數（0＝不自動清；連線歷史沒有自動清） */
  retentionDays: number | null;
}

const iso = (d: unknown): string | null => (d ? new Date(d as string | Date).toISOString() : null);

export async function historyStats(db: DB): Promise<Record<HistoryKind, HistoryStat>> {
  const e = env();
  const [[ai], [conn], [intel]] = await Promise.all([
    db.select({ n: count(), oldest: min(aiAnalyses.createdAt) }).from(aiAnalyses),
    db.select({ n: count(), oldest: min(destinations.firstSeenAt) }).from(destinations),
    db.select({ n: count(), oldest: min(ipReputation.queriedAt) }).from(ipReputation),
  ]);
  return {
    ai: { count: Number(ai.n), oldest: iso(ai.oldest), retentionDays: e.aiRetentionDays },
    connections: { count: Number(conn.n), oldest: iso(conn.oldest), retentionDays: null },
    ipintel: { count: Number(intel.n), oldest: iso(intel.oldest), retentionDays: e.ipIntelCacheDays },
  };
}

const andAll = (conds: (SQL | undefined)[]): SQL | undefined => {
  const c = conds.filter((x): x is SQL => !!x);
  return c.length ? and(...c) : undefined;
};

/** AI 分析紀錄：執行中的不刪。 */
export async function clearAiAnalyses(db: DB, opts: { before?: Date; id?: string } = {}): Promise<number> {
  const rows = await db
    .delete(aiAnalyses)
    .where(andAll([ne(aiAnalyses.status, 'running'), opts.before ? lt(aiAnalyses.createdAt, opts.before) : undefined, opts.id ? eq(aiAnalyses.id, opts.id) : undefined]))
    .returning({ id: aiAnalyses.id });
  return rows.length;
}

/** 連線歷史（看過的目的地＝可疑 IP 排名的累計）；可只清某台主機、或某天以前沒再看到的。 */
export async function clearConnectionHistory(db: DB, opts: { before?: Date; agentId?: string } = {}): Promise<number> {
  const rows = await db
    .delete(destinations)
    .where(andAll([opts.before ? lt(destinations.lastSeenAt, opts.before) : undefined, opts.agentId ? eq(destinations.agentId, opts.agentId) : undefined]))
    .returning({ ip: destinations.remoteIp });
  return rows.length;
}

/** 外部情資查詢快取（AbuseIPDB、GreyNoise…的結果）；清掉後 IP 分析頁要重新按查詢。 */
export async function clearIpIntelCache(db: DB, opts: { before?: Date } = {}): Promise<number> {
  const rows = await db
    .delete(ipReputation)
    .where(opts.before ? lt(ipReputation.queriedAt, opts.before) : undefined)
    .returning({ ip: ipReputation.ip });
  return rows.length;
}

/**
 * AI 程式自己留的對話紀錄（內含送給 AI 的主機資料）：
 * Claude Code 存在 CLAUDE_CONFIG_DIR/projects/<工作目錄>（Hub 每次分析用 asa-hub-ai-* 暫存目錄），
 * Codex 存在 CODEX_HOME/sessions。只在這兩個環境變數有設（Docker 映像預設 /data/claude、/data/codex）時才清，
 * 避免在開發機上刪到使用者自己的紀錄；登入憑證不碰。
 */
export function clearCliTranscripts(): { claude: number; codex: number; skipped: string[] } {
  const out = { claude: 0, codex: 0, skipped: [] as string[] };
  const claudeDir = process.env.CLAUDE_CONFIG_DIR?.trim();
  if (claudeDir) {
    const projects = path.join(claudeDir, 'projects');
    for (const name of safeList(projects)) {
      if (!name.includes('asa-hub-ai-')) continue;
      fs.rmSync(path.join(projects, name), { recursive: true, force: true });
      out.claude += 1;
    }
  } else out.skipped.push('CLAUDE_CONFIG_DIR');
  const codexHome = process.env.CODEX_HOME?.trim();
  if (codexHome) {
    const sessions = path.join(codexHome, 'sessions');
    for (const name of safeList(sessions)) {
      fs.rmSync(path.join(sessions, name), { recursive: true, force: true });
      out.codex += 1;
    }
  } else out.skipped.push('CODEX_HOME');
  return out;
}

function safeList(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

/** 保留期限（排程每 10 分鐘跟 metrics 彙總一起跑）：AI 分析預設 90 天、外部情資快取預設 30 天；0＝不自動清。 */
export async function pruneHistory(db: DB, now = new Date()): Promise<{ ai: number; ipintel: number }> {
  const e = env();
  const day = 86_400_000;
  const ai = e.aiRetentionDays > 0 ? await clearAiAnalyses(db, { before: new Date(now.getTime() - e.aiRetentionDays * day) }) : 0;
  const ipintel = e.ipIntelCacheDays > 0 ? await clearIpIntelCache(db, { before: new Date(now.getTime() - e.ipIntelCacheDays * day) }) : 0;
  return { ai, ipintel };
}
