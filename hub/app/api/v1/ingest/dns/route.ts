import { applyDns } from '@/lib/dns/apply';
import { env } from '@/lib/env';
import { json } from '@/lib/http';
import { handleIngest } from '@/lib/ingest/route';
import { DnsBatch } from '@/lib/ingest/schema';
import { rollupSoon } from '@/lib/metrics/rollup';

export const dynamic = 'force-dynamic';

// DNS 查詢紀錄（agent 每分鐘聚合、每分鐘送一批；離線時暫存的紀錄恢復後分批補送）。
// 限流依「這批最新紀錄的時間」比較，補送的舊批次不會被擋；同一列重送以新值覆蓋。
export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    DnsBatch,
    {
      kind: 'dns',
      agentIdOf: (b) => b.agent_id,
      minIntervalMs: env().snapshotMinIntervalMs,
      maxBytes: 2 * 1024 * 1024,
      contentTimeOf: (b) => Math.max(...b.records.map((r) => Date.parse(r.ts))),
    },
    async ({ body, db }) => {
      const r = await applyDns(db, body);
      if (r.stored) rollupSoon();
      return json({ ok: true, ...r, server_time: new Date().toISOString() });
    },
  );
}
