// 對內攻擊來源：目前連進來且判定可疑／危險的遠端 IP（跨主機彙總）。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { inboundAttackers } from '@/lib/queries/connections';
import { clampInt } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const limit = clampInt(new URL(req.url).searchParams, 'limit', 20, 1, 200);
  return json({ items: await inboundAttackers(limit) });
}
