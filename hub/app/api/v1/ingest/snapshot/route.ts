import { env } from '@/lib/env';
import { json } from '@/lib/http';
import { applySnapshot } from '@/lib/ingest/apply';
import { handleIngest } from '@/lib/ingest/route';
import { Snapshot } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    Snapshot,
    { kind: 'snapshot', agentIdOf: (b) => b.agent_id, minIntervalMs: env().snapshotMinIntervalMs, maxBytes: 2 * 1024 * 1024 },
    async ({ body, db }) => json({ ok: true, ...(await applySnapshot(db, body)) }),
  );
}
