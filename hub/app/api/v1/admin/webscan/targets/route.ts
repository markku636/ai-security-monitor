// 管理員：掃描目標清單與新增。新增時 Hub 只做 DNS 解析看位址落在哪（公網要驗證擁有權；內網要在白名單內）。
import { z } from 'zod';
import { adminAudit, adminWrite } from '@/lib/admin-write';
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { createTarget, listTargets, publicTarget } from '@/lib/webscan/targets';

export const dynamic = 'force-dynamic';

const Body = z.object({ url: z.string().min(1).max(2048), name: z.string().max(120).optional() });

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json({ items: await listTargets(getDb()) });
}

export async function POST(req: Request): Promise<Response> {
  return adminWrite(req, async (body, actor) => {
    const b = Body.parse(body);
    const r = await createTarget(getDb(), b, actor);
    if ('error' in r) return error(r.error === 'duplicate' || r.error === 'too_many_targets' ? 409 : 400, r.error);
    await adminAudit(req, actor, 'webscan.target_created', 'web_target', r.target.id, { url: r.target.url, screen: r.screen.ok ? (r.screen.internal ? 'internal' : 'public') : r.screen.reason });
    return json({ ok: true, target: publicTarget(r.target), screen: r.screen });
  });
}
