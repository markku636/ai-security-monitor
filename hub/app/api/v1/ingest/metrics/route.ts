import { env } from '@/lib/env';
import { json } from '@/lib/http';
import { handleIngest } from '@/lib/ingest/route';
import { MetricsBatch } from '@/lib/ingest/schema';
import { applyMetrics } from '@/lib/metrics/apply';
import { rollupSoon } from '@/lib/metrics/rollup';

export const dynamic = 'force-dynamic';

// 網路流量／效能樣本（agent 每分鐘一批；離線時暫存的樣本恢復後分批補送）。
// 限流依「這批最新樣本的時間」比較，補送的舊批次不會被擋；同一個樣本重送只算一次。
export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    MetricsBatch,
    {
      kind: 'metrics',
      agentIdOf: (b) => b.agent_id,
      minIntervalMs: env().snapshotMinIntervalMs,
      maxBytes: 1024 * 1024,
      contentTimeOf: (b) => Math.max(...b.samples.map((s) => Date.parse(s.ts))),
    },
    async ({ body, db }) => {
      const r = await applyMetrics(db, body);
      if (r.stored) rollupSoon();
      return json({ ok: true, ...r, server_time: new Date().toISOString() });
    },
  );
}
