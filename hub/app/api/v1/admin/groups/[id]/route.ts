// 管理員：修改主機群組（名稱、說明、成員整份取代）或刪除（只套用到它的自動回應規則會被停用）。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { deleteGroup, updateGroup } from '@/lib/response/admin';

export const dynamic = 'force-dynamic';

type Ctx = { params: Promise<{ id: string }> };

export async function PUT(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(req, async (body, actor) => {
    if (!(await updateGroup(getDb(), id, body))) return error(404, 'not_found');
    const b = body as { name?: string; members?: unknown[] };
    await adminAudit(req, actor, 'group.updated', 'group', id, { name: b.name, members: b.members?.length });
    return json({ ok: true });
  });
}

export async function DELETE(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(
    req,
    async (_b, actor) => {
      if (!(await deleteGroup(getDb(), id))) return error(404, 'not_found');
      await adminAudit(req, actor, 'group.deleted', 'group', id);
      return json({ ok: true });
    },
    { body: false },
  );
}
