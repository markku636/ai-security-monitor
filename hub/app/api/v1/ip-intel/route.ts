// IP 外部情資：GET 只讀快取（不打外部 API）；POST 由管理員觸發查詢，才會把 IP 送給第三方來源。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { actorOf, apiRead, apiWrite } from '@/lib/auth/api';
import { error, json, readJson, sourceIp } from '@/lib/http';
import { LookupsDisabled, NotPublicIp, getIpIntelView, lookupIp } from '@/lib/ipintel/service';
import { isIP } from 'node:net';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(req: Request): Promise<Response> {
  const id = await apiRead(req);
  if (id instanceof Response) return id;
  const ip = new URL(req.url).searchParams.get('ip')?.trim() ?? '';
  if (!isIP(ip)) return error(400, 'bad_ip');
  return json(await getIpIntelView(ip));
}

const Body = z.object({ ip: z.string().trim().max(64), refresh: z.boolean().default(false) });

export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 1024));
  } catch {
    return error(400, 'bad_request');
  }
  if (!isIP(body.ip)) return error(400, 'bad_ip');
  const actor = actorOf(id);
  try {
    const r = await lookupIp(body.ip, { refresh: body.refresh, actor });
    if (r.queried.length) {
      await audit({
        actor,
        actorRole: 'admin',
        action: 'ip_intel.lookup',
        targetType: 'ip',
        targetId: r.view.ip,
        sourceIp: sourceIp(req),
        details: { providers: r.queried, refresh: body.refresh },
      });
    }
    return json({ ...r.view, queried: r.queried });
  } catch (e) {
    if (e instanceof NotPublicIp) return error(400, 'not_public_ip');
    if (e instanceof LookupsDisabled) return error(409, 'lookups_disabled');
    throw e;
  }
}
