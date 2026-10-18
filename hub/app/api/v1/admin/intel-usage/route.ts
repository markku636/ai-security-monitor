// 管理員：Hub 的情資使用情境（公司／商業用途、個人／非商業用途）。非商用才鏡像只限非商業用途的來源給主機。
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { getIntelUsage, setIntelUsage } from '@/lib/intel/usage';
import { BodyTooLarge, error, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json(await getIntelUsage(getDb()));
}

export async function PUT(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: { usage?: unknown };
  try {
    body = await readJson(req, 1024);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
  const actor = actorOf(id);
  const r = await setIntelUsage(getDb(), body?.usage, actor);
  if ('error' in r) return error(r.error === 'locked_by_env' ? 409 : 400, r.error);
  await audit({
    actor,
    actorRole: 'admin',
    action: 'intel_usage.updated',
    targetType: 'setting',
    targetId: 'intel_usage',
    sourceIp: sourceIp(req),
    details: { before: r.before, after: r.after },
  });
  return json(await getIntelUsage(getDb()));
}
