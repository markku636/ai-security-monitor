// 漏洞與更新：車隊概況，或 ?agent_id= 單台最新摘要。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { agentVuln, vulnOverview } from '@/lib/queries/posture';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const agentId = new URL(req.url).searchParams.get('agent_id');
  if (agentId) {
    const v = await agentVuln(agentId);
    return v ? json(v) : json({ error: { code: 'not_found', message: 'no vulnerability summary for this agent' } }, 404);
  }
  return json(await vulnOverview());
}
