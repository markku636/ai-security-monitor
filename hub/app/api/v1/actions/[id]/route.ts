// 管理員：查看單一動作、核准／拒絕／取消（破壞性動作核准時要輸入主機名稱確認）。
import { z } from 'zod';
import { decideAction, getAction } from '@/lib/actions/store';
import { audit } from '@/lib/audit';
import { actorOf, apiRead, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

type Ctx = { params: Promise<{ id: string }> };

export async function GET(req: Request, ctx: Ctx): Promise<Response> {
  const who = await apiRead(req);
  if (who instanceof Response) return who;
  const a = await getAction(getDb(), (await ctx.params).id);
  return a ? json({ action: a }) : error(404, 'not_found');
}

const Decide = z.object({
  decision: z.enum(['approve', 'reject', 'cancel']),
  note: z.string().max(500).optional(),
  confirm_hostname: z.string().max(255).optional(),
});

const STATUS: Record<string, number> = { not_found: 404, bad_state: 409, expired: 409, agent_does_not_accept_actions: 409, confirm_hostname: 400 };

export async function POST(req: Request, ctx: Ctx): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  let body: z.infer<typeof Decide>;
  try {
    body = Decide.parse(await readJson(req, 4 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const { id } = await ctx.params;
  const actor = actorOf(who);
  const r = await decideAction(getDb(), id, body.decision, { by: actor, note: body.note, confirmHostname: body.confirm_hostname });
  if ('error' in r) return error(STATUS[r.error] ?? 400, r.error);
  await audit({
    actor,
    actorRole: 'admin',
    action: `action.${body.decision === 'approve' ? 'approved' : body.decision === 'reject' ? 'rejected' : 'cancelled'}`,
    targetType: 'action',
    targetId: id,
    sourceIp: sourceIp(req),
    details: { agent_id: r.action.agentId, kind: r.action.kind, params: r.action.params, note: body.note },
  });
  return json({ ok: true, action: r.action });
}
