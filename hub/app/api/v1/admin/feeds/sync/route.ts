// 立即同步情資（admin）：hub 先從各廠商抓最新清單；`refresh_agents` 時再叫所有主機下次心跳就更新。
import { z } from 'zod';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { audit } from '@/lib/audit';
import { getDb } from '@/lib/db';
import { error, json, sourceIp } from '@/lib/http';
import { syncFeeds } from '@/lib/intel/mirror';
import { requestRefresh } from '@/lib/intel/sync-state';

export const dynamic = 'force-dynamic';
export const maxDuration = 300;

const Body = z.object({
  force: z.boolean().default(true),
  refresh_agents: z.boolean().default(true),
  /** 只更新這些來源（每一列的「立即更新」）；沒給＝全部。 */
  only: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/)).min(1).max(200).optional(),
});

export async function POST(req: Request): Promise<Response> {
  const who = await apiWrite(req);
  if (who instanceof Response) return who;
  const parsed = Body.safeParse(await req.json().catch(() => ({})));
  if (!parsed.success) return error(400, 'bad_request');
  const outcomes = await syncFeeds({ force: parsed.data.force, only: parsed.data.only });
  if (parsed.data.refresh_agents) await requestRefresh(getDb(), actorOf(who));
  const count = (s: string) => outcomes.filter((o) => o.status === s).length;
  await audit({
    actor: actorOf(who),
    actorRole: 'admin',
    action: 'feeds.sync',
    sourceIp: sourceIp(req),
    details: { updated: count('updated'), not_modified: count('not_modified'), errors: count('error'), refresh_agents: parsed.data.refresh_agents, only: parsed.data.only ?? null },
  });
  return json({ ok: true, outcomes, refresh_agents: parsed.data.refresh_agents });
}
