// 單一代理程式：身分、狀態、分數、最近報告。
import { apiRead } from '@/lib/auth/api';
import { error, json } from '@/lib/http';
import { agentReports, getAgent } from '@/lib/queries/agents';

export const dynamic = 'force-dynamic';

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const who = await apiRead(req);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  const a = await getAgent(id);
  if (!a) return error(404, 'not_found');
  return json({ agent: a, reports: await agentReports(id, 30) });
}
