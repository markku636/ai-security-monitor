// 管理員：註冊金鑰（agent 上傳用）。明文只在建立時回傳一次。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { createEnrollKey, listEnrollKeys } from '@/lib/auth/tokens';
import { error, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json({ items: await listEnrollKeys() });
}

const Create = z.object({ name: z.string().trim().min(1).max(80) });

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Create>;
  try {
    body = Create.parse(await readJson(req, 4 * 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const actor = actorOf(id);
  const r = await createEnrollKey({ name: body.name, actor });
  await audit({ actor, actorRole: 'admin', action: 'enroll_key.created', targetType: 'enroll_key', targetId: r.row.id, sourceIp: sourceIp(req), details: { name: body.name } });
  return json({ key: r.key, item: r.row }, 201);
}
