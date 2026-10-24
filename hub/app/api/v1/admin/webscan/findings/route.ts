// 管理員：標記網站掃描的發現（已讀、忽略 N 天、重新開啟）。
import { z } from 'zod';
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { updateWebFindings } from '@/lib/webscan/findings';

export const dynamic = 'force-dynamic';

const Body = z.discriminatedUnion('action', [
  z.object({ action: z.literal('ack'), target_id: z.string().max(64), ids: z.array(z.string().max(40)).min(1).max(500) }),
  z.object({ action: z.literal('reopen'), target_id: z.string().max(64), ids: z.array(z.string().max(40)).min(1).max(500) }),
  z.object({
    action: z.literal('suppress'),
    target_id: z.string().max(64),
    ids: z.array(z.string().max(40)).min(1).max(500),
    days: z.number().int().min(1).max(365),
    reason: z.string().max(300).optional(),
  }),
]);

export async function POST(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const b = Body.parse(body);
    const op = b.action === 'suppress' ? { action: 'suppress' as const, days: b.days, reason: b.reason } : { action: b.action };
    const n = await updateWebFindings(getDb(), b.target_id, b.ids, op, actor);
    await adminAudit(req, actor, `webscan.findings_${b.action}`, 'web_target', b.target_id, { count: n });
    return json({ ok: true, updated: n });
  });
}
