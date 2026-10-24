// 網站掃描端的工作心跳：續租約、回報進度；工作被取消時回 cancel:true，已不屬於這台回 409。
import { getDb } from '@/lib/db';
import { BodyTooLarge, error, json, readJson, sourceIp } from '@/lib/http';
import { zodRule } from '@/lib/ingest/schema';
import { HeartbeatBody } from '@/lib/webscan/contract';
import { runnerAuth } from '@/lib/webscan/http';
import { heartbeatJob } from '@/lib/webscan/jobs';
import { touchRunner } from '@/lib/webscan/runners';

export const dynamic = 'force-dynamic';

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const db = getDb();
  const who = await runnerAuth(req, db, 'heartbeat', 120);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  let raw: unknown;
  try {
    raw = await readJson(req, 16 * 1024);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
  const p = HeartbeatBody.safeParse(raw);
  if (!p.success) return error(400, 'bad_request', { rule: zodRule(p.error) });
  await touchRunner(db, who, null, sourceIp(req));
  const r = await heartbeatJob(db, who, id, p.data);
  if ('error' in r) return error(409, r.error ?? 'not_claimed');
  return json(r);
}
