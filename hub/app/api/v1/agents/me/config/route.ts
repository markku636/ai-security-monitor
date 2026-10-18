// agent 取集中設定（依所屬群組合併、Hub 身分簽章）。需要 client 金鑰＋已釘選的 agent token。
import { audit } from '@/lib/audit';
import { boundToOtherAgent, clientLabel, identify } from '@/lib/auth/access';
import { signedConfig } from '@/lib/central/config';
import { getDb } from '@/lib/db';
import { error, json, sourceIp } from '@/lib/http';
import { agentTokenOf, pinAgentToken } from '@/lib/ingest/identity';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await identify(req);
  if (id.role !== 'client') return error(401, 'unauthorized');
  const agentId = req.headers.get('x-asa-agent-id')?.trim() ?? '';
  if (!agentId || agentId.length > 64) return error(400, 'bad_request', { rule: 'agent_id_header' });
  if (boundToOtherAgent(id, agentId)) return error(403, 'key_bound_to_other_agent');
  const db = getDb();
  const pin = await pinAgentToken(db, agentId, agentTokenOf(req));
  if (pin === 'unknown_agent') return error(404, 'unknown_agent');
  if (pin !== 'pinned') {
    await audit({ actor: clientLabel(id), actorRole: 'client', action: 'central_config.rejected', targetType: 'agent', targetId: agentId, sourceIp: sourceIp(req), details: { pin } });
    return error(403, pin === 'mismatch' ? 'agent_token_mismatch' : 'agent_not_pinned');
  }
  return json(await signedConfig(db, agentId));
}
