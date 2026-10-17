// 管理員：修改或刪除通知規則。
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { deleteRule, updateRule } from '@/lib/notify/admin';
import { notifyAudit, notifyWrite } from '@/lib/notify/route-helpers';

export const dynamic = 'force-dynamic';

type Ctx = { params: Promise<{ id: string }> };

export async function PUT(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return notifyWrite(req, async (body, actor) => {
    if (!(await updateRule(getDb(), id, body))) return error(404, 'not_found');
    await notifyAudit(req, actor, 'notification.rule_updated', id, { patch: body });
    return json({ ok: true });
  });
}

export async function DELETE(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return notifyWrite(
    req,
    async (_body, actor) => {
      if (!(await deleteRule(getDb(), id))) return error(404, 'not_found');
      await notifyAudit(req, actor, 'notification.rule_deleted', id);
      return json({ ok: true });
    },
    { body: false },
  );
}
