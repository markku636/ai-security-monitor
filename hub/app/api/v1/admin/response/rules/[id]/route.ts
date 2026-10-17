// 管理員：修改或刪除自動回應規則。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { deleteResponseRule, updateResponseRule } from '@/lib/response/admin';

export const dynamic = 'force-dynamic';

type Ctx = { params: Promise<{ id: string }> };

export async function PUT(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(req, async (body, actor) => {
    if (!(await updateResponseRule(getDb(), id, body))) return error(404, 'not_found');
    await adminAudit(req, actor, 'response.rule_updated', 'response_rule', id, { patch: body });
    return json({ ok: true });
  });
}

export async function DELETE(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(
    req,
    async (_b, actor) => {
      if (!(await deleteResponseRule(getDb(), id))) return error(404, 'not_found');
      await adminAudit(req, actor, 'response.rule_deleted', 'response_rule', id);
      return json({ ok: true });
    },
    { body: false },
  );
}
