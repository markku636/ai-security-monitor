// 車隊級連線查詢（每個 agent 的最新快照）：方向、判定、情資來源、國家、關鍵字。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { listConnections, parseConnectionFilter } from '@/lib/queries/connections';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const f = parseConnectionFilter(new URL(req.url).searchParams);
  const r = await listConnections(f);
  return json({ ...r, limit: f.limit, offset: f.offset });
}
