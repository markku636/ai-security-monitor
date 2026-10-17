// i18n（與 agent / db-kit 同一套慣例）：繁中原文即 key，查無譯文回原文；`{name}` 插值。
import { en } from '@/messages/en';

export type Lang = 'zh-TW' | 'en';
export const LANGS: Lang[] = ['zh-TW', 'en'];
export const LANG_COOKIE = 'asa_lang';
export const THEME_COOKIE = 'asa_theme';

export type Params = Record<string, string | number>;

export function interpolate(tpl: string, params?: Params): string {
  if (!params) return tpl;
  return tpl.replace(/\{([A-Za-z0-9_]+)\}/g, (whole, key: string) =>
    Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : whole,
  );
}

export function translate(zh: string, params: Params | undefined, lang: Lang): string {
  const tpl = lang === 'en' ? (en[zh] ?? zh) : zh;
  return interpolate(tpl, params);
}

/** cookie ＞ Accept-Language（en* → en）＞ zh-TW。 */
export function resolveLang(cookie: string | undefined, acceptLanguage: string | null | undefined): Lang {
  if (cookie === 'en' || cookie === 'zh-TW') return cookie;
  const first = (acceptLanguage ?? '').split(',')[0]?.trim().toLowerCase() ?? '';
  return first.startsWith('en') ? 'en' : 'zh-TW';
}

export type TFn = (zh: string, params?: Params) => string;

export function makeT(lang: Lang): TFn {
  // 附上語言，讓只拿到 t 的元件也能用 Intl（例如國名）
  return Object.assign((zh: string, params?: Params) => translate(zh, params, lang), { lang });
}

/** t 是用哪個語言建的（makeT 附上的；拿不到就當繁中）。 */
export function langOf(t: TFn): Lang {
  return (t as TFn & { lang?: Lang }).lang ?? 'zh-TW';
}
