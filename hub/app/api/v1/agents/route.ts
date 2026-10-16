import { identify } from '@/lib/auth/access';
import { error, json } from '@/lib/http';
import { listAgents } from '@/lib/queries/agents';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await identify(req);
  if (id.role !== 'admin' && id.role !== 'viewer') return error(401, 'unauthorized');
  const rows = await listAgents();
  // 公開檢視不露 IP、版本等細節。
  const items =
    id.role === 'viewer'
      ? rows.map((a) => ({ id: a.id, hostname: a.hostname, status: a.status, score: a.score, sev_counts: a.sevCounts }))
      : rows.map((a) => ({
          id: a.id,
          hostname: a.hostname,
          os: { family: a.osFamily, name: a.osName, version: a.osVersion },
          arch: a.arch,
          version: a.version,
          ips: a.ips,
          status: a.status,
          elevated: a.elevated,
          partial: a.partial,
          score: a.score,
          sev_counts: a.sevCounts,
          open_findings: a.openFindings,
          last_seen_at: a.lastSeenAt,
          last_report_at: a.lastReportAt,
        }));
  return json({ items, total: items.length });
}
