// 管理員：新增主機群組（名稱、說明、成員）。
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { createGroup } from '@/lib/response/admin';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const id = await createGroup(getDb(), body, actor);
    const b = body as { name?: string; members?: unknown[] };
    await adminAudit(req, actor, 'group.created', 'group', id, { name: b.name, members: b.members?.length ?? 0 });
    return json({ id }, 201);
  });
}
