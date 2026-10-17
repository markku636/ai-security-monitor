// 管理員：免金鑰加入申請清單（不含 secret 雜湊、金鑰或憑證）。
import { apiAdminRead } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { getAutoApproveCidrs, listRequests } from '@/lib/enroll/store';
import { json } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  const status = new URL(req.url).searchParams.get('status') === 'all' ? 'all' : 'pending';
  const db = getDb();
  const r = await listRequests(db, { status });
  return json({ ...r, auto_approve_cidrs: await getAutoApproveCidrs(db) });
}
