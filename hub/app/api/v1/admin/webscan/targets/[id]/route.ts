// 管理員：單一掃描目標（驗證狀態、工作、發現）與刪除（排隊中／執行中的工作一併取消）。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { deleteTarget } from '@/lib/webscan/targets';
import { targetDetail } from '@/lib/webscan/view';

export const dynamic = 'force-dynamic';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const who = await apiAdminRead(req);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  const d = await targetDetail(getDb(), id);
  return d ? json(d) : error(404, 'not_found');
}

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  return adminWrite(
    req,
    async (_body, actor) => {
      if (!(await deleteTarget(getDb(), id))) return error(404, 'not_found');
      await adminAudit(req, actor, 'webscan.target_deleted', 'web_target', id);
      return json({ ok: true });
    },
    { body: false },
  );
}
