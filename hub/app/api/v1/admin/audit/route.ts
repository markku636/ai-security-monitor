// 管理員：稽核紀錄（最新在前）。
import { apiAdminRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { listAudit } from '@/lib/queries/admin';
import { clampInt, strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  const sp = new URL(req.url).searchParams;
  return json({ items: await listAudit({ limit: clampInt(sp, 'limit', 100, 1, 1000), action: strParam(sp, 'action', 64) }) });
}
