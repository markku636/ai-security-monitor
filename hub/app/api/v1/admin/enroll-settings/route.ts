// 管理員：免金鑰加入的設定（自動核准網段）與自動尋找狀態（mDNS、DNS SRV 紀錄）。
import { audit } from '@/lib/audit';
import { actorOf, apiAdminRead, apiWrite } from '@/lib/auth/api';
import { getDb } from '@/lib/db';
import { mdnsStatus } from '@/lib/discovery/mdns';
import { srvInfo } from '@/lib/discovery/srv';
import { MAX_CIDRS } from '@/lib/enroll/cidr';
import { hubIdentity, hubName, keylessEnabled } from '@/lib/enroll/identity';
import { getAutoApproveCidrs, setAutoApproveCidrs } from '@/lib/enroll/store';
import { env } from '@/lib/env';
import { BodyTooLarge, error, json, peerIpHookInstalled, readJson, sourceIp } from '@/lib/http';
import { hubPublicUrl } from '@/lib/install';

export const dynamic = 'force-dynamic';

async function view(req: Request) {
  const db = getDb();
  const id = await hubIdentity(db);
  const publicUrl = hubPublicUrl(req.headers, req.url);
  return {
    auto_approve_cidrs: await getAutoApproveCidrs(db),
    enroll_requests_enabled: keylessEnabled(),
    peer_ip_available: peerIpHookInstalled() || env().trustProxy,
    mdns: mdnsStatus(),
    hub: { name: hubName(), fingerprint: id.fingerprint, public_url: publicUrl },
    srv: srvInfo(publicUrl, id.fingerprint),
  };
}

export async function GET(req: Request): Promise<Response> {
  const id = await apiAdminRead(req);
  if (id instanceof Response) return id;
  return json(await view(req));
}

export async function PUT(req: Request): Promise<Response> {
  const id = await apiWrite(req);
  if (id instanceof Response) return id;
  let body: { auto_approve_cidrs?: unknown };
  try {
    body = await readJson(req, 16 * 1024);
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, 'bad_request');
  }
  const list = body?.auto_approve_cidrs;
  if (!Array.isArray(list) || list.length > MAX_CIDRS) return error(400, 'bad_request', { rule: 'auto_approve_cidrs' });
  const actor = actorOf(id);
  const r = await setAutoApproveCidrs(getDb(), list, actor);
  if ('error' in r) return error(400, r.error, { value: r.value });
  await audit({ actor, actorRole: 'admin', action: 'enroll_settings.updated', targetType: 'settings', targetId: 'enroll_auto_approve_cidrs', sourceIp: sourceIp(req), details: { before: r.before, after: r.after } });
  return json(await view(req));
}
