// 清除歷史（admin）：GET＝各類筆數、最舊時間、保留天數；DELETE ?kind=ai|connections|ipintel
// [&older_than_days=N][&agent_id=…（只限 connections）][&cli=1（只限 ai：一併刪 AI 程式的對話紀錄）]。
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { clearAiAnalyses, clearCliTranscripts, clearConnectionHistory, clearIpIntelCache, HISTORY_KINDS, historyStats, type HistoryKind } from '@/lib/history';
import { error, json, sourceIp } from '@/lib/http';
import { clampInt, strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const who = await apiAdminRead(req);
  if (who instanceof Response) return who;
  return json({ stats: await historyStats(getDb()) });
}

export async function DELETE(req: Request): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const sp = new URL(req.url).searchParams;
  const kind = sp.get('kind') as HistoryKind | null;
  if (!kind || !(HISTORY_KINDS as readonly string[]).includes(kind)) return error(400, 'bad_request', { rule: 'kind' });
  const days = clampInt(sp, 'older_than_days', 0, 0, 3650);
  const before = days > 0 ? new Date(Date.now() - days * 86_400_000) : undefined;
  const agentId = kind === 'connections' ? strParam(sp, 'agent_id', 64) : undefined;
  const db = getDb();
  let deleted = 0;
  let cli: ReturnType<typeof clearCliTranscripts> | null = null;
  if (kind === 'ai') {
    deleted = await clearAiAnalyses(db, { before });
    if (sp.get('cli') === '1') cli = clearCliTranscripts();
  } else if (kind === 'connections') {
    deleted = await clearConnectionHistory(db, { before, agentId });
  } else {
    deleted = await clearIpIntelCache(db, { before });
  }
  await audit({
    actor: actorOf(who),
    actorRole: 'admin',
    action: 'history.cleared',
    targetType: 'history',
    targetId: kind,
    sourceIp: sourceIp(req),
    details: { deleted, older_than_days: days || null, agent_id: agentId ?? null, cli },
  });
  return json({ ok: true, kind, deleted, cli, stats: await historyStats(db) });
}
