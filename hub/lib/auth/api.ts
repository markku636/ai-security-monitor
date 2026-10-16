// API route 的身分閘門：回傳 Identity，或直接回 401／403 Response。
import { error } from '@/lib/http';
import { identify, sameSiteWrite, type Identity } from './access';

/** 讀取：admin（含 Bearer）；`allowViewer` 時公開檢視也可（只給彙總資料的端點用）。 */
export async function apiRead(req: Request, opts: { allowViewer?: boolean } = {}): Promise<Identity | Response> {
  const id = await identify(req);
  if (id.role === 'admin') return id;
  if (opts.allowViewer && id.role === 'viewer') return id;
  return error(401, 'unauthorized');
}

/** 寫入：只限 admin；cookie 身分另外要過 CSRF 檢查。 */
export async function apiWrite(req: Request): Promise<Identity | Response> {
  const id = await identify(req);
  if (id.role !== 'admin') return error(401, 'unauthorized');
  if (id.via !== 'bearer' && !sameSiteWrite(req)) return error(403, 'cross_site_request');
  return id;
}

/** 稽核用的操作者名稱。 */
export function actorOf(id: Identity): string {
  return id.via === 'open' ? 'admin:open' : id.via === 'bearer' ? 'admin:bearer' : 'admin:session';
}
