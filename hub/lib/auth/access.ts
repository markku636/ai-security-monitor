// 身分判斷（沿用 open-token-monitor 的三種金鑰）：
//   admin  ASA_HUB_ADMIN_SECRET（Bearer）或登入後的 session cookie
//   client ASA_HUB_CLIENT_SECRETS（agent 上傳用）
//   viewer 不帶金鑰，只在 ASA_HUB_PUBLIC_DASHBOARD 時
// 沒設管理員金鑰＝開放模式：所有人都是 admin（只能綁 loopback，見 scripts/start.mjs）。
import { env, isOpenMode } from '@/lib/env';
import { parseCookies } from '@/lib/http';
import { safeEqual } from './crypto';
import { SESSION_COOKIE, validateSession } from './sessions';

export type Role = 'admin' | 'client' | 'viewer' | 'none';
export type Via = 'open' | 'session' | 'bearer' | 'public' | 'none';

export interface Identity {
  role: Role;
  via: Via;
  /** client 金鑰的序號（第幾把），稽核用。 */
  keyIndex?: number;
}

export function bearer(req: Request): string | undefined {
  const h = req.headers.get('authorization') ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m?.[1]?.trim() || undefined;
}

export async function identifyByCredentials(token: string | undefined, cookieToken: string | undefined): Promise<Identity> {
  const e = env();
  if (isOpenMode()) return { role: 'admin', via: 'open' };
  if (token) {
    if (safeEqual(token, e.adminSecret)) return { role: 'admin', via: 'bearer' };
    const idx = e.clientSecrets.findIndex((s) => safeEqual(token, s));
    if (idx >= 0) return { role: 'client', via: 'bearer', keyIndex: idx };
    return { role: 'none', via: 'none' };
  }
  if (cookieToken && (await validateSession(cookieToken))) return { role: 'admin', via: 'session' };
  if (e.publicDashboard) return { role: 'viewer', via: 'public' };
  return { role: 'none', via: 'none' };
}

export async function identify(req: Request): Promise<Identity> {
  return identifyByCredentials(bearer(req), parseCookies(req)[SESSION_COOKIE]);
}

/**
 * cookie 身分的寫入要防 CSRF：自訂標頭 X-ASA-Request＋Sec-Fetch-Site 同站。
 * Bearer 身分不需要（瀏覽器不會自動附帶）。
 */
export function sameSiteWrite(req: Request): boolean {
  if (req.headers.get('x-asa-request') !== '1') return false;
  const site = req.headers.get('sec-fetch-site');
  if (site && site !== 'same-origin' && site !== 'none') return false;
  const origin = req.headers.get('origin');
  if (origin) {
    try {
      if (new URL(origin).host !== new URL(req.url).host && new URL(origin).host !== req.headers.get('host')) return false;
    } catch {
      return false;
    }
  }
  return true;
}

export function canRead(id: Identity): boolean {
  return id.role === 'admin' || id.role === 'viewer';
}
