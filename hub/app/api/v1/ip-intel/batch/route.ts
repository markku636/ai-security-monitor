// 批次查詢外部情資：管理員在可疑 IP 排名勾選後按「查詢外部情資」。一次最多 50 個（畫面每 5 個送一次，顯示進度）。
// 內網／保留位址不送出（回 skipped）；快取內的不重打；每日額度照常自我節流。
import { isIP } from 'node:net';
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiWrite } from '@/lib/auth/api';
import { error, json, readJson, sourceIp } from '@/lib/http';
import { normalizeIp } from '@/lib/ipintel/ip';
import { BATCH_MAX, LookupsDisabled, lookupBatch } from '@/lib/ipintel/service';

export const dynamic = 'force-dynamic';
export const maxDuration = 300;

const Body = z.object({
  ips: z.array(z.string().trim().max(64)).min(1).max(BATCH_MAX),
  force: z.boolean().default(false),
});

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 8 * 1024));
  } catch {
    return error(400, 'bad_request', { max: BATCH_MAX });
  }
  const invalid = body.ips.filter((s) => !isIP(s));
  if (invalid.length) return error(400, 'bad_ip', { invalid: invalid.slice(0, 10) });
  const ips = [...new Set(body.ips.map(normalizeIp))];
  const actor = actorOf(id);
  let items;
  try {
    items = await lookupBatch(ips, { refresh: body.force, actor });
  } catch (e) {
    if (e instanceof LookupsDisabled) return error(409, 'lookups_disabled');
    throw e;
  }
  const summary = {
    count: items.length,
    queried: items.filter((r) => !r.skipped && !r.error && !r.cached).length,
    cached: items.filter((r) => !r.skipped && !r.error && r.cached).length,
    skipped: items.filter((r) => r.skipped).length,
    errors: items.filter((r) => r.error).length,
  };
  await audit({
    actor,
    actorRole: 'admin',
    action: 'ip_intel.batch',
    targetType: 'ip',
    targetId: `${items.length} IPs`,
    sourceIp: sourceIp(req),
    details: { ...summary, force: body.force, ips: items.filter((r) => !r.skipped).map((r) => r.ip) },
  });
  return json({ items, summary });
}
