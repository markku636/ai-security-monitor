// 刪除一筆 AI 分析紀錄（admin；執行中的不刪）。
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { clearAiAnalyses } from '@/lib/history';
import { error, json, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const { id } = await ctx.params;
  if (!/^ai_[0-9a-f]{16}$/.test(id)) return error(404, 'not_found');
  const n = await clearAiAnalyses(getDb(), { id });
  if (!n) return error(404, 'not_found_or_running');
  await audit({ actor: actorOf(who), actorRole: 'admin', action: 'ai_analysis.deleted', targetType: 'ai_analysis', targetId: id, sourceIp: sourceIp(req) });
  return json({ ok: true });
}
