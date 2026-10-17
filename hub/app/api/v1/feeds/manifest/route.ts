// agent 取情資鏡像清單（client 金鑰、admin 或 read token）；順便觸發背景補抓。
import { boundToOtherAgent, identify } from '@/lib/auth/access';
import { getDb } from '@/lib/db';
import { error, json } from '@/lib/http';
import { manifest, mirrorAllowed, syncInBackground, syncRunning } from '@/lib/intel/mirror';
import { refreshRequestedAt } from '@/lib/intel/sync-state';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await identify(req);
  if (!mirrorAllowed(id)) return error(401, 'unauthorized');
  if (boundToOtherAgent(id, req.headers.get('x-asa-agent-id')?.trim())) return error(403, 'key_bound_to_other_agent');
  syncInBackground();
  const requested = await refreshRequestedAt(getDb());
  return json({ feeds: manifest(), syncing: syncRunning(), refresh_requested_at: requested?.toISOString() ?? null, server_time: new Date().toISOString() });
}
