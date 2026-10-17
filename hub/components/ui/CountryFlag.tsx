// 國旗＋國家代碼（server component）：Windows 不顯示國旗 emoji，所以用內建 SVG（country-flag-icons，MIT）。
// 滑過顯示完整國名（依介面語言，Intl.DisplayNames）。
import * as svgs from 'country-flag-icons/string/3x2';
import { langOf, type TFn } from '@/lib/i18n/core';
import { Tooltip } from './Tooltip';

const FLAGS = svgs as unknown as Record<string, string | undefined>;

const names: Partial<Record<string, Intl.DisplayNames>> = {};
export function countryName(code: string, lang: 'zh-TW' | 'en'): string {
  try {
    names[lang] ??= new Intl.DisplayNames([lang], { type: 'region' });
    return names[lang]!.of(code) ?? code;
  } catch {
    return code;
  }
}

export function CountryFlag({ code, t, showCode = true }: { code: string | null | undefined; t: TFn; showCode?: boolean }) {
  const c = (code ?? '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(c)) return null;
  const svg = FLAGS[c];
  const name = countryName(c, langOf(t));
  return (
    <Tooltip text={name} className="inline-flex cursor-help items-center gap-1 align-middle">
      {svg ? (
        <span
          className="inline-block h-3 w-[18px] shrink-0 overflow-hidden rounded-[2px] ring-1 ring-black/10 dark:ring-white/15 [&>svg]:h-full [&>svg]:w-full"
          aria-hidden
          // 套件內建的靜態 SVG（不是使用者輸入）
          dangerouslySetInnerHTML={{ __html: svg }}
        />
      ) : null}
      {showCode ? <span className="font-mono text-[11px]">{c}</span> : <span className="sr-only">{name}</span>}
    </Tooltip>
  );
}
