// 查一個 IP／網域：列名的情資來源、目前連線、歷史目的地。
import { apiRead } from '@/lib/auth/api';
import { error, json } from '@/lib/http';
import { lookupIndicator } from '@/lib/queries/intel';
import { strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const q = strParam(new URL(req.url).searchParams, 'q', 100);
  if (!q) return error(400, 'bad_request', { rule: 'q' });
  return json({ q, ...(await lookupIndicator(q)) });
}
