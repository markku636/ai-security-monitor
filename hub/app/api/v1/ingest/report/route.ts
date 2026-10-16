import { eq } from 'drizzle-orm';
import { reports } from '@/drizzle/schema';
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
    {
      kind: 'report',
      agentIdOf: (b) => b.agent.id,
      minIntervalMs: env().reportMinIntervalMs,
      // 依報告完成時間判斷間隔：斷線期間暫存的報告恢復後可一次補送。
      contentTimeOf: (b) => Date.parse(b.finished_at),
      precheck: async (b, db) => {
        const seen = await db.select({ id: reports.id }).from(reports).where(eq(reports.id, b.report_id)).limit(1);
        if (!seen.length) return null;
        return json({
          ok: true,
          report_id: b.report_id,
          duplicate: true,
          findings: { new: 0, updated: 0, unchanged: 0, reopened: 0, resolved: 0 },
          min_interval_ms: env().reportMinIntervalMs,
          server_time: new Date().toISOString(),
        });
      },
    },
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
