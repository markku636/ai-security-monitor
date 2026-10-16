import { audit } from '@/lib/audit';
import { env } from '@/lib/env';
import { json } from '@/lib/http';
import { applyRegister } from '@/lib/ingest/apply';
import { handleIngest } from '@/lib/ingest/route';
import { Register } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    Register,
    { kind: 'register', agentIdOf: (b) => b.agent.id, minIntervalMs: 0, maxBytes: 64 * 1024 },
    async ({ body, id, db, ip }) => {
      const r = await applyRegister(db, body, id.keyIndex);
      if (r.created) {
        await audit({
          actor: `client:${id.keyIndex ?? 'admin'}`,
          actorRole: id.role,
          action: 'agent.registered',
          targetType: 'agent',
          targetId: r.agent_id,
          sourceIp: ip,
          details: { hostname: body.agent.hostname, os: body.agent.os.family, version: body.agent.version },
        });
      }
      const e = env();
      return json({
        agent_id: r.agent_id,
        created: r.created,
        hub: {
          name: 'Security Hub',
          version: e.version,
          min_report_interval_s: Math.ceil(e.reportMinIntervalMs / 1000),
          snapshot_interval_s: Math.max(60, Math.ceil(e.snapshotMinIntervalMs / 1000)),
          max_report_bytes: 4 * 1024 * 1024,
          server_time: new Date().toISOString(),
        },
      });
    },
  );
}
