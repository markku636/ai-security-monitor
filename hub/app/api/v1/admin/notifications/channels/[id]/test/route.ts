// 管理員：對頻道送一則測試訊息（馬上送、不進佇列），回傳成功或錯誤原因。
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { notifyAudit, notifyWrite } from '@/lib/notify/route-helpers';
import { sendTest } from '@/lib/notify/service';

export const dynamic = 'force-dynamic';
export const maxDuration = 30;

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  return notifyWrite(
    req,
    async (_body, actor) => {
      const r = await sendTest(getDb(), id);
      if (r.error === 'not_found') return error(404, 'not_found');
      await notifyAudit(req, actor, 'notification.channel_tested', id, { ok: r.ok });
      return json(r);
    },
    { body: false },
  );
}
