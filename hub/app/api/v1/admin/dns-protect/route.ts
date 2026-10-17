// 管理員：防護 DNS 的設定（開關、上游、清單、自訂封鎖／允許）、暫停、伺服器狀態與封鎖統計。
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { pauseProtect, protectView, setProtect } from '@/lib/dns/protect';
import { BodyTooLarge, error, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json(await protectView(getDb()));
}

async function body(req: Request): Promise<Record<string, unknown> | Response> {
  try {
    const b = await readJson<Record<string, unknown>>(req, 512 * 1024);
    return b && typeof b === 'object' && !Array.isArray(b) ? b : error(400, 'bad_request');
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
}

export async function PUT(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  const b = await body(req);
  if (b instanceof Response) return b;
  const actor = actorOf(id);
  const r = await setProtect(getDb(), b, actor);
  if ('error' in r) return error(400, r.error);
  const changed = Object.keys(r.after).filter((k) => JSON.stringify(r.after[k as keyof typeof r.after]) !== JSON.stringify(r.before[k as keyof typeof r.before]));
  await audit({ actor, actorRole: 'admin', action: 'dns_protect.updated', targetType: 'settings', targetId: 'dns_protect', sourceIp: sourceIp(req), details: { changed, enabled: r.after.enabled } });
  return json({ ok: true, settings: r.after });
}

/** 暫停封鎖：`{ pause_minutes: 5 }`；0＝立刻恢復。 */
export async function POST(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  const b = await body(req);
  if (b instanceof Response) return b;
  const m = Number(b.pause_minutes);
  if (!Number.isFinite(m) || m < 0) return error(400, 'bad_request', { rule: 'pause_minutes' });
  const actor = actorOf(id);
  const s = await pauseProtect(getDb(), m, actor);
  await audit({ actor, actorRole: 'admin', action: m > 0 ? 'dns_protect.paused' : 'dns_protect.resumed', targetType: 'settings', targetId: 'dns_protect', sourceIp: sourceIp(req), details: { minutes: m } });
  return json({ ok: true, settings: s });
}
