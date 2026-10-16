// agent 回報遠端動作的執行結果。
import { z } from 'zod';
import { recordResult } from '@/lib/actions/store';
import { audit } from '@/lib/audit';
import { error, json } from '@/lib/http';
import { handleIngest } from '@/lib/ingest/route';

export const dynamic = 'force-dynamic';

const Result = z.object({
  agent_id: z.string().min(1).max(64),
  ok: z.boolean(),
  output: z.string().max(64 * 1024).default(''),
});

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id: actionId } = await ctx.params;
  return handleIngest(
    req,
    Result,
    { kind: 'action_result', agentIdOf: (b) => b.agent_id, minIntervalMs: 0, maxBytes: 80 * 1024 },
    async ({ body, db, pin, ip, id }) => {
      if (pin !== 'pinned') return error(403, 'agent_not_pinned');
      const r = await recordResult(db, body.agent_id, actionId, { ok: body.ok, output: body.output });
      if ('error' in r) return error(r.error === 'not_found' ? 404 : 409, r.error);
      await audit({
        actor: `agent:${body.agent_id}`,
        actorRole: id.role,
        action: body.ok ? 'action.succeeded' : 'action.failed',
        targetType: 'action',
        targetId: actionId,
        sourceIp: ip,
        details: { kind: r.action.kind, params: r.action.params, output: body.output.slice(0, 500) },
      });
      return json({ ok: true, status: r.action.status });
    },
  );
}
