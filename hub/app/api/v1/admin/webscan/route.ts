// 管理員：網站掃描總覽（設定、掃描端在線狀態、目標清單、最近的工作）。
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { json } from '@/lib/http';
import { webscanView } from '@/lib/webscan/view';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json(await webscanView(getDb()));
}
