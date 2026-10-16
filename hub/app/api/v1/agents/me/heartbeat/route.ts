import { env } from '@/lib/env';
import { error, json } from '@/lib/http';
import { applyHeartbeat } from '@/lib/ingest/apply';
import { handleIngest } from '@/lib/ingest/route';
import { Heartbeat } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    Heartbeat,
    { kind: 'heartbeat', agentIdOf: (b) => b.agent_id, minIntervalMs: env().snapshotMinIntervalMs, maxBytes: 8 * 1024 },
    async ({ body, db }) => {
      if (!(await applyHeartbeat(db, body))) return error(404, 'unknown_agent', { hint: 'register first' });
      return json({ ok: true, server_time: new Date().toISOString(), pending_actions: 0 });
    },
  );
}
