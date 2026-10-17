// 管理員：修改（名稱、啟用、設定；祕密欄位留空＝沿用）或刪除通知頻道。
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { deleteChannel, updateChannel } from '@/lib/notify/admin';
import { notifyAudit, notifyWrite } from '@/lib/notify/route-helpers';

export const dynamic = 'force-dynamic';

type Ctx = { params: Promise<{ id: string }> };

export async function PUT(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return notifyWrite(req, async (body, actor) => {
    if (!(await updateChannel(getDb(), id, body))) return error(404, 'not_found');
    const b = body as { name?: string; enabled?: boolean; config?: unknown };
    await notifyAudit(req, actor, 'notification.channel_updated', id, { name: b.name, enabled: b.enabled, config_changed: b.config !== undefined });
    return json({ ok: true });
  });
}

export async function DELETE(req: Request, ctx: Ctx): Promise<Response> {
  const { id } = await ctx.params;
  return notifyWrite(
    req,
    async (_body, actor) => {
      if (!(await deleteChannel(getDb(), id))) return error(404, 'not_found');
      await notifyAudit(req, actor, 'notification.channel_deleted', id);
      return json({ ok: true });
    },
    { body: false },
  );
}
