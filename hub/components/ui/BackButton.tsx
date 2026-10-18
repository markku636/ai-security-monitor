'use client';

// 內頁的「← 回上一頁」：從 Hub 裡點進來的就真的回上一頁（篩選、分頁、捲動位置都保留）；
// 直接打開網址或重新整理過的，沒有站內上一頁可回，改去上層頁面（fallback）。
// NavTracker 放在版面裡記錄站內有沒有換過頁（只存在記憶體，整頁重新載入就重算）。
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useEffect } from 'react';
import { useT } from '@/lib/i18n/client';

let first: string | null = null;
let moved = false;

export function NavTracker() {
  const path = usePathname();
  const query = useSearchParams().toString();
  useEffect(() => {
    const here = `${path}?${query}`;
    if (first === null) first = here;
    else if (here !== first) moved = true;
  }, [path, query]);
  return null;
}

export function BackButton({ fallback }: { fallback: string }) {
  const { t } = useT();
  const router = useRouter();
  return (
    <a
      href={fallback}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        if (moved && window.history.length > 1) router.back();
        else router.push(fallback);
      }}
      className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-0.5 text-xs text-slate-600 hover:border-teal-600 hover:text-teal-700 dark:border-slate-700 dark:text-slate-300 dark:hover:text-teal-400"
    >
      <span aria-hidden>←</span>
      {t('回上一頁')}
    </a>
  );
}
