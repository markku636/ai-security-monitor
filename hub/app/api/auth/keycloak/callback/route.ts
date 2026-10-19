import { audit } from '@/lib/audit';
import { safeEqual } from '@/lib/auth/crypto';
import {
  discoverKeycloak,
  exchangeKeycloakCode,
  keycloakActor,
  keycloakClaimAllowed,
  keycloakLoginConfig,
  keycloakRedirectUri,
  keycloakTransientCookie,
  verifyKeycloakIdToken,
  KEYCLOAK_NONCE_COOKIE,
  KEYCLOAK_STATE_COOKIE,
  KEYCLOAK_VERIFIER_COOKIE,
} from '@/lib/auth/keycloak';
import { createSession, SESSION_TTL_MS, sessionCookie } from '@/lib/auth/sessions';
import { isHttps, parseCookies, sourceIp } from '@/lib/http';

export const dynamic = 'force-dynamic';

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status: 302, headers });
}

function clearTransient(secure: boolean): string[] {
  return [KEYCLOAK_STATE_COOKIE, KEYCLOAK_NONCE_COOKIE, KEYCLOAK_VERIFIER_COOKIE].map((name) =>
    keycloakTransientCookie(name, '', secure, 0),
  );
}

export async function GET(req: Request): Promise<Response> {
  const cfg = keycloakLoginConfig();
  const secure = isHttps(req);
  const clear = clearTransient(secure);
  if (!cfg.enabled) return redirect('/login?error=keycloak_disabled', clear);
  const url = new URL(req.url);
  const code = url.searchParams.get('code') ?? '';
  const state = url.searchParams.get('state') ?? '';
  const cookies = parseCookies(req);
  const expectedState = cookies[KEYCLOAK_STATE_COOKIE] ?? '';
  const nonce = cookies[KEYCLOAK_NONCE_COOKIE] ?? '';
  const verifier = cookies[KEYCLOAK_VERIFIER_COOKIE] ?? '';
  if (!code || !state || !expectedState || !nonce || !verifier || !safeEqual(state, expectedState)) {
    await audit({ actor: 'anonymous', actorRole: 'none', action: 'auth.keycloak_failed', sourceIp: sourceIp(req), details: { reason: 'invalid_state' } });
    return redirect('/login?error=keycloak_state', clear);
  }
  try {
    const discovery = await discoverKeycloak(cfg);
    const redirectUri = keycloakRedirectUri(req.headers, req.url);
    const tokens = await exchangeKeycloakCode(discovery, cfg, { code, verifier, redirectUri });
    const payload = await verifyKeycloakIdToken(tokens.id_token!, discovery, cfg, nonce);
    if (!keycloakClaimAllowed(payload, cfg)) {
      await audit({ actor: keycloakActor(payload), actorRole: 'none', action: 'auth.keycloak_denied', sourceIp: sourceIp(req) });
      return redirect('/login?error=keycloak_denied', clear);
    }
    const { token } = await createSession(sourceIp(req));
    const actor = keycloakActor(payload);
    await audit({ actor, actorRole: 'admin', action: 'auth.login', sourceIp: sourceIp(req), details: { via: 'keycloak', subject: payload.sub } });
    return redirect('/', [...clear, sessionCookie(token, Math.floor(SESSION_TTL_MS / 1000), secure)]);
  } catch (error) {
    await audit({
      actor: 'anonymous',
      actorRole: 'none',
      action: 'auth.keycloak_failed',
      sourceIp: sourceIp(req),
      details: { reason: error instanceof Error ? error.message.slice(0, 200) : 'unknown' },
    });
    return redirect('/login?error=keycloak_failed', clear);
  }
}
