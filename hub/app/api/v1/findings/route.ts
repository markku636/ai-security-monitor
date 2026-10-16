// GET：篩選發現（含 facets）；POST：批次確認／暫停／重新開啟（最多 500 筆，寫稽核）。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiRead, apiWrite } from '@/lib/auth/api';
import { error, json, readJson, sourceIp } from '@/lib/http';
import { bulkUpdateFindings, listFindings, parseFindingFilter, toFindingView } from '@/lib/queries/findings';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const f = parseFindingFilter(new URL(req.url).searchParams);
  const r = await listFindings(f);
  return json({ items: r.items.map(toFindingView), total: r.total, facets: r.facets, limit: f.limit, offset: f.offset });
}

const Bulk = z.object({
  action: z.enum(['ack', 'suppress', 'reopen']),
  keys: z
    .array(z.object({ agent_id: z.string().min(1).max(64), finding_id: z.string().min(1).max(64) }))
    .min(1)
    .max(500),
  days: z.number().int().min(1).max(365).optional(),
  reason: z.string().max(500).optional(),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Bulk>;
  try {
    body = Bulk.parse(await readJson(req, 256 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const actor = actorOf(id);
  const r = await bulkUpdateFindings(body.keys, body.action, { actor, days: body.days, reason: body.reason });
  await audit({
    actor,
    actorRole: 'admin',
    action: `findings.${body.action}`,
    targetType: 'finding',
    targetId: body.keys.length === 1 ? `${body.keys[0].agent_id}/${body.keys[0].finding_id}` : undefined,
    sourceIp: sourceIp(req),
    details: { requested: body.keys.length, changed: r.changed, agents: r.agents, days: body.days, reason: body.reason },
  });
  return json({ ok: true, changed: r.changed });
}
