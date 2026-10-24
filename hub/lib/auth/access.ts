// 身分判斷（沿用 open-token-monitor 的三種金鑰）：
//   admin  ASA_HUB_ADMIN_SECRET（Bearer）或登入後的 session cookie
//   client ASA_HUB_CLIENT_SECRETS（agent 上傳用）
//   viewer 不帶金鑰，只在 ASA_HUB_PUBLIC_DASHBOARD 時
//   reader 網頁建立的 API token（唯讀，依 scope：read／export／mcp／dns／webscan）；compose 內建防護 DNS 的 ASA_HUB_DNS_TOKEN 等同 dns 權杖，
//          compose 內建網站掃描端的 ASA_HUB_WEBSCAN_TOKEN 等同 webscan 權杖
// 網頁建立的註冊金鑰（asa_ek_…）等同 client。
// 沒設管理員金鑰＝開放模式：所有人都是 admin（只能綁 loopback，見 scripts/start.mjs）。
import { env, isOpenMode, readEnv } from '@/lib/env';
import { count, hit } from '@/lib/auth/ratelimit';
import { sourceIp } from '@/lib/http';
import { parseCookies } from '@/lib/http';
import { safeEqual } from './crypto';
import { SESSION_COOKIE, validateSession } from './sessions';
import { isApiTokenShape, isEnrollKeyShape, verifyApiToken, verifyEnrollKey, type TokenScope } from './tokens';

export type Role = 'admin' | 'client' | 'viewer' | 'reader' | 'none';
export type Via = 'open' | 'session' | 'bearer' | 'public' | 'enroll' | 'token' | 'none';

export interface Identity {
  role: Role;
  via: Via;
  /** client 金鑰的序號（第幾把），稽核用。 */
  keyIndex?: number;
  /** 網頁建立的註冊金鑰 id。 */
  enrollKeyId?: string;
  /** 這把註冊金鑰只准哪台 agent 用（免金鑰加入核准發的金鑰）；其他 agent id 一律 403。 */
  boundAgentId?: string;
  /** API token id 與 scope。 */
  tokenId?: string;
  scopes?: TokenScope[];
}

/** 綁定一台 agent 的金鑰被拿來替別的 agent id 用？（沒綁定 → 永遠 false） */
export function boundToOtherAgent(id: Identity, agentId: string | null | undefined): boolean {
  return !!id.boundAgentId && !!agentId && id.boundAgentId !== agentId;
}

/** 稽核用的 client 名稱：環境變數第幾把，或註冊金鑰 id。 */
export function clientLabel(id: Identity): string {
  if (id.enrollKeyId) return `client:ek_${id.enrollKeyId}`;
  return `client:${id.keyIndex ?? 'admin'}`;
}

export function hasScope(id: Identity, scope: TokenScope): boolean {
  return id.role === 'reader' && !!id.scopes?.includes(scope);
}

export function bearer(req: Request): string | undefined {
  const h = req.headers.get('authorization') ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m?.[1]?.trim() || undefined;
}

/** Host／Origin 是不是本機（localhost、127.0.0.1、::1）。 */
export function isLoopbackHost(h: string | null | undefined): boolean {
  if (!h) return false;
  const host = h.replace(/^https?:\/\//, '').split('/')[0];
  const name = host.startsWith('[') ? host.slice(1, host.indexOf(']')) : host.split(':')[0];
  return name === 'localhost' || name === '127.0.0.1' || name === '::1';
}

/**
 * 開放模式（沒設管理員金鑰）只給用本機網址連進來的人：擋 DNS rebinding（惡意網頁把自己的網域指到 127.0.0.1）與區網直連。
 * Docker 明確設 AI_SECURITY_MONITOR_HUB_ALLOW_OPEN_MODE=1（只在 docker 網路內用）時照舊。
 */
export function openModeAllowed(host: string | null | undefined): boolean {
  return ['1', 'true', 'yes', 'on'].includes(readEnv('ASA_HUB_ALLOW_OPEN_MODE').toLowerCase()) || isLoopbackHost(host);
}

export async function identifyByCredentials(token: string | undefined, cookieToken: string | undefined, host?: string | null): Promise<Identity> {
  const e = env();
  if (isOpenMode()) return openModeAllowed(host) ? { role: 'admin', via: 'open' } : { role: 'none', via: 'none' };
  if (token) {
    if (safeEqual(token, e.adminSecret)) return { role: 'admin', via: 'bearer' };
    const idx = e.clientSecrets.findIndex((s) => safeEqual(token, s));
    if (idx >= 0) return { role: 'client', via: 'bearer', keyIndex: idx };
    if (e.dnsServerToken && safeEqual(token, e.dnsServerToken)) return { role: 'reader', via: 'bearer', tokenId: 'env', scopes: ['dns'] };
    if (e.webscanToken && safeEqual(token, e.webscanToken)) return { role: 'reader', via: 'bearer', tokenId: 'env-webscan', scopes: ['webscan'] };
    if (isEnrollKeyShape(token)) {
      const k = await verifyEnrollKey(token);
      if (k) return { role: 'client', via: 'enroll', enrollKeyId: k.id, ...(k.boundAgentId ? { boundAgentId: k.boundAgentId } : {}) };
    } else if (isApiTokenShape(token)) {
      const t = await verifyApiToken(token);
      if (t) return { role: 'reader', via: 'token', tokenId: t.id, scopes: t.scopes };
    }
    return { role: 'none', via: 'none' };
  }
  if (cookieToken && (await validateSession(cookieToken))) return { role: 'admin', via: 'session' };
  if (e.publicDashboard) return { role: 'viewer', via: 'public' };
  return { role: 'none', via: 'none' };
}

/** 猜 Bearer 金鑰的煞車：同一個來源 10 分鐘內失敗 100 次就先全部擋掉（正確的金鑰也一樣，否則猜中就進得來）。 */
const BEARER_FAIL_WINDOW_MS = 10 * 60_000;
const BEARER_FAIL_MAX = 100;

export async function identify(req: Request): Promise<Identity> {
  const token = bearer(req);
  if (token && !isOpenMode()) {
    const key = `bearer-fail:${sourceIp(req)}`;
    if (count(key, BEARER_FAIL_WINDOW_MS) >= BEARER_FAIL_MAX) return { role: 'none', via: 'none' };
    const id = await identifyByCredentials(token, undefined);
    if (id.role === 'none') hit(key, BEARER_FAIL_WINDOW_MS);
    return id;
  }
  return identifyByCredentials(token, parseCookies(req)[SESSION_COOKIE], req.headers.get('host'));
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
