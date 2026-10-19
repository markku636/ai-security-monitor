import {
  buildGoogleAuthorizationUrl,
  createGoogleRequest,
  discoverGoogle,
  googleLoginConfig,
  googleRedirectUri,
  googleTransientCookie,
  GOOGLE_NONCE_COOKIE,
  GOOGLE_STATE_COOKIE,
  GOOGLE_VERIFIER_COOKIE,
} from '@/lib/auth/google';
import { isHttps } from '@/lib/http';

export const dynamic = 'force-dynamic';

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status: 302, headers });
}

export async function GET(req: Request): Promise<Response> {
  const cfg = googleLoginConfig();
  if (!cfg.enabled) return redirect('/login?error=google_disabled');
  try {
    const discovery = await discoverGoogle(cfg);
    const redirectUri = googleRedirectUri(req.headers, req.url);
    const googleRequest = createGoogleRequest();
    const secure = isHttps(req);
    return redirect(buildGoogleAuthorizationUrl(discovery, cfg, redirectUri, googleRequest), [
      googleTransientCookie(GOOGLE_STATE_COOKIE, googleRequest.state, secure),
      googleTransientCookie(GOOGLE_NONCE_COOKIE, googleRequest.nonce, secure),
      googleTransientCookie(GOOGLE_VERIFIER_COOKIE, googleRequest.verifier, secure),
    ]);
  } catch {
    return redirect('/login?error=google_unavailable');
  }
}
