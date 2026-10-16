// agent 領取已核准的遠端動作（附 HMAC token）。需要 client 金鑰＋已釘選的 agent token。
import { eq } from 'drizzle-orm';
import { agents } from '@/drizzle/schema';
import { dispatchForAgent } from '@/lib/actions/store';
import { audit } from '@/lib/audit';
import { identify } from '@/lib/auth/access';
import { getDb } from '@/lib/db';
import { error, json, sourceIp } from '@/lib/http';
import { agentTokenOf, pinAgentToken } from '@/lib/ingest/identity';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await identify(req);
  if (id.role !== 'client') return error(401, 'unauthorized');
  const agentId = req.headers.get('x-asa-agent-id')?.trim() ?? '';
  if (!agentId || agentId.length > 64) return error(400, 'bad_request', { rule: 'agent_id_header' });
  const db = getDb();
  const pin = await pinAgentToken(db, agentId, agentTokenOf(req));
  if (pin === 'unknown_agent') return error(404, 'unknown_agent');
  if (pin !== 'pinned') {
    await audit({ actor: `client:${id.keyIndex}`, actorRole: 'client', action: 'actions.poll.rejected', targetType: 'agent', targetId: agentId, sourceIp: sourceIp(req), details: { pin } });
    return error(403, pin === 'mismatch' ? 'agent_token_mismatch' : 'agent_not_pinned');
  }
  const a = (await db.select({ accept: agents.acceptRemoteActions }).from(agents).where(eq(agents.id, agentId)).limit(1))[0];
  if (!a?.accept) return json({ items: [] });
  const items = await dispatchForAgent(db, agentId);
  return json({ items, server_time: new Date().toISOString() });
}
