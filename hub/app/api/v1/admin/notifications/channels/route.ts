// 管理員：新增通知頻道（祕密欄位加密存放，稽核不記設定內容）。
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { createChannel } from '@/lib/notify/admin';
import { notifyAudit, notifyWrite } from '@/lib/notify/route-helpers';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return notifyWrite(req, async (body, actor) => {
    const id = await createChannel(getDb(), body, actor);
    const b = body as { kind?: string; name?: string };
    await notifyAudit(req, actor, 'notification.channel_created', id, { kind: b.kind, name: b.name });
    return json({ id }, 201);
  });
}
