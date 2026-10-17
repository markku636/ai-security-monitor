import { openActionCount } from '@/lib/actions/store';
import { env } from '@/lib/env';
import { error, json } from '@/lib/http';
import { applyHeartbeat } from '@/lib/ingest/apply';
import { handleIngest } from '@/lib/ingest/route';
import { Heartbeat } from '@/lib/ingest/schema';
import { refreshRequestedAt, shouldRefresh } from '@/lib/intel/sync-state';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    Heartbeat,
    { kind: 'heartbeat', agentIdOf: (b) => b.agent_id, minIntervalMs: env().snapshotMinIntervalMs, maxBytes: 8 * 1024 },
    async ({ body, db, pin }) => {
      if (!(await applyHeartbeat(db, body))) return error(404, 'unknown_agent', { hint: 'register first' });
      const pending = pin === 'pinned' ? await openActionCount(db, body.agent_id) : 0;
      // 有人按了「叫所有主機更新情資」且這台還沒更新 → 叫它更新（舊版 agent 會忽略 commands）
      const checked = body.intel_checked_at ? new Date(body.intel_checked_at) : null;
      const commands = shouldRefresh(await refreshRequestedAt(db), checked) ? ['refresh_feeds'] : [];
      return json({ ok: true, server_time: new Date().toISOString(), pending_actions: pending, commands });
    },
  );
}
