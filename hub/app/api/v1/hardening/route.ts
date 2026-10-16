// 系統硬化：車隊概況（各主機分數、最常未通過），或 ?agent_id= 單台每條檢查結果。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { agentHardening, hardeningOverview } from '@/lib/queries/posture';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const agentId = new URL(req.url).searchParams.get('agent_id');
  if (agentId) {
    const h = await agentHardening(agentId);
    return h ? json(h) : json({ error: { code: 'not_found', message: 'no hardening summary for this agent' } }, 404);
  }
  return json(await hardeningOverview());
}
