import { audit } from '@/lib/audit';
import { safeEqual } from '@/lib/auth/crypto';
import {
  discoverGoogle,
  exchangeGoogleCode,
  googleActor,
  googleClaimAllowed,
  googleLoginConfig,
  googleRedirectUri,
  googleTransientCookie,
  verifyGoogleIdToken,
  GOOGLE_NONCE_COOKIE,
  GOOGLE_STATE_COOKIE,
  GOOGLE_VERIFIER_COOKIE,
} from '@/lib/auth/google';
import { createSession, SESSION_TTL_MS, sessionCookie } from '@/lib/auth/sessions';
import { isHttps, parseCookies, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status: 302, headers });
}

function clearTransient(secure: boolean): string[] {
  return [GOOGLE_STATE_COOKIE, GOOGLE_NONCE_COOKIE, GOOGLE_VERIFIER_COOKIE].map((name) =>
    googleTransientCookie(name, '', secure, 0),
  );
}

export async function GET(req: Request): Promise<Response> {
  const cfg = googleLoginConfig();
  const secure = isHttps(req);
  const clear = clearTransient(secure);
  if (!cfg.enabled) return redirect('/login?error=google_disabled', clear);
  const url = new URL(req.url);
  const code = url.searchParams.get('code') ?? '';
  const state = url.searchParams.get('state') ?? '';
  const cookies = parseCookies(req);
  const expectedState = cookies[GOOGLE_STATE_COOKIE] ?? '';
  const nonce = cookies[GOOGLE_NONCE_COOKIE] ?? '';
  const verifier = cookies[GOOGLE_VERIFIER_COOKIE] ?? '';
  if (!code || !state || !expectedState || !nonce || !verifier || !safeEqual(state, expectedState)) {
    await audit({ actor: 'anonymous', actorRole: 'none', action: 'auth.google_failed', sourceIp: sourceIp(req), details: { reason: 'invalid_state' } });
    return redirect('/login?error=google_state', clear);
  }
  try {
    const discovery = await discoverGoogle(cfg);
    const redirectUri = googleRedirectUri(req.headers, req.url);
    const tokens = await exchangeGoogleCode(discovery, cfg, { code, verifier, redirectUri });
    const payload = await verifyGoogleIdToken(tokens.id_token!, discovery, cfg, nonce);
    if (!googleClaimAllowed(payload, cfg)) {
      await audit({ actor: googleActor(payload), actorRole: 'none', action: 'auth.google_denied', sourceIp: sourceIp(req) });
      return redirect('/login?error=google_denied', clear);
    }
    const { token } = await createSession(sourceIp(req));
    const actor = googleActor(payload);
    await audit({ actor, actorRole: 'admin', action: 'auth.login', sourceIp: sourceIp(req), details: { via: 'google', subject: payload.sub } });
    // Finish the cross-site navigation before sending the Strict session cookie.
    // A 302 chain from Google can reach / without that cookie and bounce to /login.
    const headers = new Headers({
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    });
    for (const cookie of [...clear, sessionCookie(token, Math.floor(SESSION_TTL_MS / 1000), secure)]) {
      headers.append('set-cookie', cookie);
    }
    return new Response('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/"><title>Security Hub</title></head><body><a href="/">Continue to Security Hub</a></body></html>', { status: 200, headers });
  } catch (error) {
    await audit({
      actor: 'anonymous',
      actorRole: 'none',
      action: 'auth.google_failed',
      sourceIp: sourceIp(req),
      details: { reason: error instanceof Error ? error.message.slice(0, 200) : 'unknown' },
    });
    return redirect('/login?error=google_failed', clear);
  }
}
