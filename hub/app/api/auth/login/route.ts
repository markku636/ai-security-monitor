// 管理員登入：貼上 ASA_HUB_ADMIN_SECRET → HttpOnly session cookie。每 IP 每分鐘最多 5 次失敗。
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { sameSiteWrite } from '@/lib/auth/access';
import { safeEqual } from '@/lib/auth/crypto';
import { clear, count, hit } from '@/lib/auth/ratelimit';
import { createSession, SESSION_TTL_MS, sessionCookie } from '@/lib/auth/sessions';
import { env, isOpenMode } from '@/lib/env';
import { BodyTooLarge, error, isHttps, json, readJson, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

const Body = z.object({ key: z.string().min(1).max(4096) });
const WINDOW_MS = 60_000;
const MAX_FAILS = 5;

export async function POST(req: Request): Promise<Response> {
  if (!sameSiteWrite(req)) return error(403, 'cross_site_request');
  if (isOpenMode()) return json({ ok: true, role: 'admin', via: 'open' });
  const ip = sourceIp(req);
  const rlKey = `login:${ip}`;
  if (count(rlKey, WINDOW_MS) >= MAX_FAILS) {
    return json({ error: 'too_many_attempts' }, 429, { 'retry-after': '60' });
  }
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 8192));
  } catch (e) {
    return error(e instanceof BodyTooLarge ? 413 : 400, e instanceof BodyTooLarge ? 'too_large' : 'bad_request');
  }
  if (!safeEqual(body.key.trim(), env().adminSecret)) {
    hit(rlKey, WINDOW_MS);
    await audit({ actor: 'anonymous', actorRole: 'none', action: 'auth.login_failed', sourceIp: ip });
    return error(401, 'invalid_key');
  }
  clear(rlKey);
  const { token, expiresAt } = await createSession(ip);
  await audit({ actor: 'admin', actorRole: 'admin', action: 'auth.login', sourceIp: ip });
  return json(
    { ok: true, role: 'admin', via: 'session', expires_at: expiresAt.toISOString() },
    200,
    { 'set-cookie': sessionCookie(token, Math.floor(SESSION_TTL_MS / 1000), isHttps(req)) },
  );
}
