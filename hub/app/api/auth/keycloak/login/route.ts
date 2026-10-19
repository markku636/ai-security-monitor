import {
  buildKeycloakAuthorizationUrl,
  createKeycloakRequest,
  discoverKeycloak,
  keycloakLoginConfig,
  keycloakRedirectUri,
  keycloakTransientCookie,
  KEYCLOAK_NONCE_COOKIE,
  KEYCLOAK_STATE_COOKIE,
  KEYCLOAK_VERIFIER_COOKIE,
} from '@/lib/auth/keycloak';
import { isHttps } from '@/lib/http';

export const dynamic = 'force-dynamic';

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status: 302, headers });
}

export async function GET(req: Request): Promise<Response> {
  const cfg = keycloakLoginConfig();
  if (!cfg.enabled) return redirect('/login?error=keycloak_disabled');
  try {
    const discovery = await discoverKeycloak(cfg);
    const redirectUri = keycloakRedirectUri(req.headers, req.url);
    const keycloakRequest = createKeycloakRequest();
    const secure = isHttps(req);
    return redirect(buildKeycloakAuthorizationUrl(discovery, cfg, redirectUri, keycloakRequest), [
      keycloakTransientCookie(KEYCLOAK_STATE_COOKIE, keycloakRequest.state, secure),
      keycloakTransientCookie(KEYCLOAK_NONCE_COOKIE, keycloakRequest.nonce, secure),
      keycloakTransientCookie(KEYCLOAK_VERIFIER_COOKIE, keycloakRequest.verifier, secure),
    ]);
  } catch {
    return redirect('/login?error=keycloak_unavailable');
  }
}
