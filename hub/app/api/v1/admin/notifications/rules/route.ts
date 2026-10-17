// 管理員：新增通知規則（只通知建立之後發生的事）。
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { createRule } from '@/lib/notify/admin';
import { notifyAudit, notifyWrite } from '@/lib/notify/route-helpers';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return notifyWrite(req, async (body, actor) => {
    const id = await createRule(getDb(), body, actor);
    await notifyAudit(req, actor, 'notification.rule_created', id, { rule: body });
    return json({ id }, 201);
  });
}
