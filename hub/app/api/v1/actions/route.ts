// 管理員：列出／建立遠端動作。建立後是 pending，要再核准才會派送給 agent。
import { z } from 'zod';
import { ACTION_STATUSES, createAction, listActions } from '@/lib/actions/store';
import { audit } from '@/lib/audit';
import { actorOf, apiRead, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json, readJson, sourceIp } from '@/lib/http';
import { clampInt, listParam, strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const sp = new URL(req.url).searchParams;
  const r = await listActions(getDb(), {
    status: listParam(sp, 'status', ACTION_STATUSES),
    agentId: strParam(sp, 'agent_id', 64),
    limit: clampInt(sp, 'limit', 100, 1, 200),
    offset: clampInt(sp, 'offset', 0, 0, 100_000),
  });
  return json(r);
}

const Create = z.object({
  agent_id: z.string().min(1).max(64),
  kind: z.string().max(32),
  params: z.record(z.string(), z.unknown()),
  finding_id: z.string().max(64).optional(),
  reason: z.string().max(500).optional(),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Create>;
  try {
    body = Create.parse(await readJson(req, 16 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const actor = actorOf(id);
  const r = await createAction(getDb(), {
    agentId: body.agent_id,
    kind: body.kind,
    params: body.params,
    findingId: body.finding_id,
    reason: body.reason,
    proposedBy: actor,
  });
  if ('error' in r) {
    const status = r.error === 'agent_not_found' ? 404 : r.error === 'duplicate' ? 409 : 400;
    return error(status, r.error);
  }
  await audit({
    actor,
    actorRole: 'admin',
    action: 'action.proposed',
    targetType: 'action',
    targetId: r.action.id,
    sourceIp: sourceIp(req),
    details: { agent_id: body.agent_id, kind: r.action.kind, params: r.action.params, finding_id: body.finding_id },
  });
  return json({ ok: true, action: r.action }, 201);
}
