// 介面偏好（語言 / 主題）存在 cookie，伺服器端渲染時就能套用（不閃爍）。
import { z } from 'zod';
import { sameSiteWrite } from '@/lib/auth/access';
import { error, readJson } from '@/lib/http';
import { LANG_COOKIE, THEME_COOKIE } from '@/lib/i18n/core';

export const dynamic = 'force-dynamic';

const Body = z.object({
  lang: z.enum(['zh-TW', 'en']).optional(),
  theme: z.enum(['light', 'dark', 'system']).optional(),
});

const YEAR = 365 * 24 * 3600;

export async function POST(req: Request): Promise<Response> {
  if (!sameSiteWrite(req)) return error(403, 'cross_site_request');
  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await readJson(req, 1024));
  } catch {
    return error(400, 'bad_request');
  }
  const headers = new Headers({ 'content-type': 'application/json' });
  if (body.lang) headers.append('set-cookie', `${LANG_COOKIE}=${body.lang}; Path=/; Max-Age=${YEAR}; SameSite=Lax`);
  if (body.theme) headers.append('set-cookie', `${THEME_COOKIE}=${body.theme}; Path=/; Max-Age=${YEAR}; SameSite=Lax`);
  // 可能要設兩個 cookie，json() 的單一標頭物件放不下，直接組 Response。
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}
