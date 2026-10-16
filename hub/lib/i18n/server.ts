import { cookies, headers } from 'next/headers';
import { LANG_COOKIE, makeT, resolveLang, type Lang, type TFn } from './core';

export async function getLang(): Promise<Lang> {
  const c = await cookies();
  const h = await headers();
  return resolveLang(c.get(LANG_COOKIE)?.value, h.get('accept-language'));
}

export async function getT(): Promise<{ t: TFn; lang: Lang }> {
  const lang = await getLang();
  return { t: makeT(lang), lang };
}
