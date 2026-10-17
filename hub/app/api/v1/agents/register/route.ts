import { clientLabel } from '@/lib/auth/access';
import { actionKeyFor, signingKey } from '@/lib/actions/sign';
import { audit } from '@/lib/audit';
import { hubName } from '@/lib/enroll/identity';
import { markClaimed } from '@/lib/enroll/store';
import { env } from '@/lib/env';
import { json } from '@/lib/http';
import { applyRegister } from '@/lib/ingest/apply';
import { pinAgentToken } from '@/lib/ingest/identity';
import { handleIngest } from '@/lib/ingest/route';
import { Register } from '@/lib/ingest/schema';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  return handleIngest(
    req,
    Register,
    { kind: 'register', agentIdOf: (b) => b.agent.id, minIntervalMs: 0, maxBytes: 64 * 1024 },
    async ({ body, id, db, ip, agentToken }) => {
      const r = await applyRegister(db, body, id.keyIndex, id.enrollKeyId);
      // 新 agent：寫入後才釘選得到。
      const pin = await pinAgentToken(db, r.agent_id, agentToken);
      // 用免金鑰加入核准發的金鑰註冊成功 → 申請標成已領取（10 分鐘後輪詢就不再回憑證）
      if (id.enrollKeyId && id.boundAgentId) await markClaimed(db, id.enrollKeyId);
      if (r.created) {
        await audit({
          actor: clientLabel(id),
          actorRole: id.role,
          action: 'agent.registered',
          targetType: 'agent',
          targetId: r.agent_id,
          sourceIp: ip,
          details: { hostname: body.agent.hostname, os: body.agent.os.family, version: body.agent.version },
        });
      }
      const e = env();
      // 只有身分已釘選、且願意接受遠端動作的 agent 才拿得到驗章金鑰。
      const actionKey =
        body.accept_remote_actions && pin === 'pinned' ? actionKeyFor(await signingKey(db), r.agent_id) : undefined;
      return json({
        agent_id: r.agent_id,
        created: r.created,
        pinned: pin === 'pinned',
        ...(actionKey ? { action_key: actionKey } : {}),
        hub: {
          name: hubName(),
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
