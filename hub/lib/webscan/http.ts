// webscan runner 端點的共用：辨認掃描端身分＋限流，錯誤碼對應。
import { identify } from '@/lib/auth/access';
import { hit } from '@/lib/auth/ratelimit';
import type { DB } from '@/lib/db';
import { error, json } from '@/lib/http';
import { webscanRunnerOf, type RunnerWho } from './runners';

/** 掃描端身分（webscan 權杖）＋每分鐘次數上限；不是掃描端回 401，太頻繁回 429。 */
export async function runnerAuth(req: Request, db: DB, bucket: string, perMinute: number): Promise<RunnerWho | Response> {
  const who = await webscanRunnerOf(await identify(req), db);
  if (!who) return error(401, 'unauthorized');
  if (hit(`webscan-${bucket}:${who.id}`, 60_000) > perMinute) return json({ error: 'too_frequent', retry_after_ms: 60_000 }, 429, { 'retry-after': '60' });
  return who;
}

/** 建立工作／驗證時的錯誤碼 → HTTP 狀態。 */
export function jobErrorStatus(code: string): number {
  if (code === 'target_not_found' || code === 'not_found') return 404;
  if (code === 'duplicate' || code === 'bad_state') return 409;
  if (code.startsWith('blocked_target:')) return 422;
  return 400;
}
