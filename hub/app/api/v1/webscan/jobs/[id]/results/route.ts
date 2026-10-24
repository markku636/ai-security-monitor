// 網站掃描端回報工作結束（contract/webscan-result.v1.json）：Hub 解析原始輸出、更新發現；驗證工作更新擁有權。
import { getDb } from '@/lib/db';
import { BodyTooLarge, error, json, readJson } from '@/lib/http';
import { zodRule } from '@/lib/ingest/schema';
import { ResultBody } from '@/lib/webscan/contract';
import { runnerAuth } from '@/lib/webscan/http';
import { finishJob } from '@/lib/webscan/jobs';

export const dynamic = 'force-dynamic';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const db = getDb();
  const who = await runnerAuth(req, db, 'results', 60);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  let raw: unknown;
  try {
    raw = await readJson(req, 256 * 1024);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
  const p = ResultBody.safeParse(raw);
  if (!p.success) return error(400, 'bad_request', { rule: zodRule(p.error) });
  const r = await finishJob(db, who, id, p.data);
  if ('error' in r) return error(409, r.error ?? 'not_claimed');
  return json(r);
}
