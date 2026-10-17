// 免金鑰加入：電腦端用申請時的 request_secret（Bearer）輪詢；核准後才回綁定這台的註冊金鑰（附 Hub 簽章）。
// 不存在與 secret 錯誤回一樣的 404；同一來源失敗太多次 → 429。
import { bearer } from '@/lib/auth/access';
import { count, hit } from '@/lib/auth/ratelimit';
import { getDb } from '@/lib/db';
import { expireStale, findForPoll, pollView } from '@/lib/enroll/store';
import { error, json, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

const FAIL_WINDOW_MS = 10 * 60_000;
const MAX_FAILURES = 30;

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const key = `enroll_poll_fail:${sourceIp(req)}`;
  if (count(key, FAIL_WINDOW_MS) >= MAX_FAILURES) {
    return json({ error: 'too_many_requests', retry_after_ms: FAIL_WINDOW_MS }, 429, { 'retry-after': String(FAIL_WINDOW_MS / 1000) });
  }
  const { id } = await ctx.params;
  const db = getDb();
  await expireStale(db);
  const row = await findForPoll(db, id, bearer(req));
  if (!row) {
    hit(key, FAIL_WINDOW_MS);
    return error(404, 'not_found');
  }
  return json(await pollView(db, row));
}
