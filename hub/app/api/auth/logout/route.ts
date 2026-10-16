import { sameSiteWrite } from '@/lib/auth/access';
import { deleteSession, SESSION_COOKIE, sessionCookie } from '@/lib/auth/sessions';
import { error, isHttps, json, parseCookies } from '@/lib/http';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  if (!sameSiteWrite(req)) return error(403, 'cross_site_request');
  await deleteSession(parseCookies(req)[SESSION_COOKIE]);
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0, isHttps(req)) });
}
