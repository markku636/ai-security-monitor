// agent 身分釘選（TOFU）：client 金鑰是多台共用的，光靠它擋不住「拿同一把金鑰冒充別台 agent」。
// agent 在 enroll 時產生一組隨機 token，之後每個請求帶 X-ASA-Agent-Token；hub 第一次看到時記下 sha256，
// 之後不符就 403。遠端動作（取得 action_key、領取動作、回報結果）一律要求已釘選。
import { and, eq, isNull } from 'drizzle-orm';
import { agents } from '@/drizzle/schema';
import type { DB } from '@/lib/db';
import { safeEqual, sha256Hex } from '@/lib/auth/crypto';

export const AGENT_TOKEN_HEADER = 'x-asa-agent-token';

export type PinResult = 'pinned' | 'unpinned' | 'unknown_agent' | 'mismatch';

export function agentTokenOf(req: Request): string | null {
  const v = req.headers.get(AGENT_TOKEN_HEADER)?.trim() ?? '';
  return v.length >= 16 && v.length <= 128 ? v : null;
}

/**
 * 檢查（必要時釘選）agent token：
 * - 還沒有這台 agent → unknown_agent（註冊後再呼叫一次就會釘選）
 * - 尚未釘選且請求帶 token → 釘選 → pinned；沒帶 → unpinned
 * - 已釘選：相符 → pinned；不符或沒帶 → mismatch
 */
export async function pinAgentToken(db: DB, agentId: string, token: string | null): Promise<PinResult> {
  const row = (await db.select({ tokenHash: agents.tokenHash }).from(agents).where(eq(agents.id, agentId)).limit(1))[0];
  if (!row) return 'unknown_agent';
  if (row.tokenHash) return token && safeEqual(sha256Hex(token), row.tokenHash) ? 'pinned' : 'mismatch';
  if (!token) return 'unpinned';
  const set = await db
    .update(agents)
    .set({ tokenHash: sha256Hex(token) })
    .where(and(eq(agents.id, agentId), isNull(agents.tokenHash)))
    .returning({ id: agents.id });
  // 同時有別的請求先釘選了 → 重新比對一次。
  return set.length ? 'pinned' : pinAgentToken(db, agentId, token);
}
