import { env } from '@/lib/env';
import { json } from '@/lib/http';
import { applyReport } from '@/lib/ingest/apply';
import { handleIngest } from '@/lib/ingest/route';
import { Report } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    Report,
    { kind: 'report', agentIdOf: (b) => b.agent.id, minIntervalMs: env().reportMinIntervalMs },
    async ({ body, id, db, ip, bytes }) => {
      const r = await applyReport(db, body, { sourceIp: ip, bytes, keyIndex: id.keyIndex });
      return json({
        ok: true,
        report_id: r.report_id,
        duplicate: r.duplicate,
        findings: r.findings,
        min_interval_ms: env().reportMinIntervalMs,
        server_time: new Date().toISOString(),
      });
    },
  );
}
