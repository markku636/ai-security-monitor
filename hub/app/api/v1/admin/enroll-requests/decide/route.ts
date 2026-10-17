// 管理員：核准／拒絕免金鑰加入申請（只動 pending 的；每筆一條稽核）。
import { z } from 'zod';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { decide } from '@/lib/enroll/store';
import { error, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

const Body = z.object({
  ids: z.array(z.string().regex(/^rq_[0-9a-f]{24}$/)).min(1).max(200),
  decision: z.enum(['approve', 'reject']),
  reason: z.string().trim().max(500).optional(),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 32 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const items = await decide(getDb(), body.ids, body.decision, { actor: actorOf(id), reason: body.reason || null, sourceIp: sourceIp(req) });
  return json({ updated: items.length, items });
}
