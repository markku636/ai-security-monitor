// API route 的身分閘門：回傳 Identity，或直接回 401／403 Response。
import { error } from '@/lib/http';
import { hasScope, identify, sameSiteWrite, type Identity } from './access';
import type { TokenScope } from './tokens';

/**
 * 讀取：admin（含 Bearer）或帶對應 scope 的 API token（預設 read）；
 * `allowViewer` 時公開檢視也可（只給彙總資料的端點用）。
 */
export async function apiRead(req: Request, opts: { allowViewer?: boolean; scope?: TokenScope } = {}): Promise<Identity | Response> {
  const id = await identify(req);
  if (id.role === 'admin') return id;
  if (hasScope(id, opts.scope ?? 'read')) return id;
  if (opts.allowViewer && id.role === 'viewer') return id;
  if (id.role === 'reader') return error(403, 'insufficient_scope');
  return error(401, 'unauthorized');
}

/** 管理功能的讀取（金鑰、稽核）：只限 admin，API token 一律不行。 */
export async function apiAdminRead(req: Request): Promise<Identity | Response> {
  const id = await identify(req);
  if (id.role === 'admin') return id;
  return error(id.role === 'reader' ? 403 : 401, id.role === 'reader' ? 'insufficient_scope' : 'unauthorized');
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
  if (id.role === 'reader') return `token:${id.tokenId}`;
  return id.via === 'open' ? 'admin:open' : id.via === 'bearer' ? 'admin:bearer' : 'admin:session';
}
