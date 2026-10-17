// 管理員：新增自動回應規則。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { createResponseRule } from '@/lib/response/admin';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const id = await createResponseRule(getDb(), body, actor);
    await adminAudit(req, actor, 'response.rule_created', 'response_rule', id, { rule: body });
    return json({ id }, 201);
  });
}
