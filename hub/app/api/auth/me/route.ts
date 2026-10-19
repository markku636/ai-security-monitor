import { identify } from '@/lib/auth/access';
import { env, isOpenMode, keycloakLoginEnabled } from '@/lib/env';
import { json, parseCookies } from '@/lib/http';
import { LANG_COOKIE, resolveLang } from '@/lib/i18n/core';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const id = await identify(req);
  return json({
    role: id.role,
    via: id.via,
    open_mode: isOpenMode(),
    keycloak_enabled: keycloakLoginEnabled(),
    public_dashboard: env().publicDashboard,
    lang: resolveLang(parseCookies(req)[LANG_COOKIE], req.headers.get('accept-language')),
  });
}
