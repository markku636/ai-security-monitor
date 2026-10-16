// 車隊總覽：代理程式狀態、嚴重度、危險連線數、平均分數、情資來源命中（公開檢視只給彙總，不含 IP）。
import { apiRead } from '@/lib/auth/api';
import { json } from '@/lib/http';
import { averageScore, fleetSummary, listAgents } from '@/lib/queries/agents';
import { topIntelFeeds } from '@/lib/queries/intel';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req, { allowViewer: true });
  if (id instanceof Response) return id;
  const [fleet, list, feeds] = await Promise.all([fleetSummary(), listAgents(), topIntelFeeds(7, 10)]);
  return json({
    ...fleet,
    score: averageScore(list),
    intel_feeds: feeds.map((f) => ({
      feed_id: f.feedId,
      name: f.feedName,
      vendor: f.vendor,
      license: f.license,
      source_url: f.sourceUrl,
      max_confidence: f.maxConfidence,
      indicators: f.indicators,
      hosts: f.hosts,
      last_seen_at: f.lastSeenAt,
    })),
  });
}
