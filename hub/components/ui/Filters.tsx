// 篩選晶片（純連結，不需要 client JS）與分頁。
import Link from 'next/link';
import type { ReactNode } from 'react';
import type { TFn } from '@/lib/i18n/core';

export function FilterChip({ href, active, children }: { href: string; active: boolean; children: ReactNode }) {
  return (
    <Link
      href={href}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs ${
        active
          ? 'border-teal-600 bg-teal-600 text-white'
          : 'border-slate-300 text-slate-700 hover:border-slate-400 dark:border-slate-700 dark:text-slate-300'
      }`}
      aria-current={active ? 'true' : undefined}
    >
      {children}
    </Link>
  );
}

export function FilterRow({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="mr-1 w-14 shrink-0 text-xs text-slate-500">{label}</span>
      {children}
    </div>
  );
}

/** 切換清單裡的某個值（多選篩選用）。 */
export function toggled<T extends string>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

export function Pager({
  t,
  total,
  limit,
  offset,
  hrefFor,
}: {
  t: TFn;
  total: number;
  limit: number;
  offset: number;
  hrefFor: (offset: number) => string;
}) {
  if (total <= limit) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <nav className="flex items-center justify-between text-sm text-slate-500">
      <span>{t('第 {from}–{to} 筆，共 {total} 筆', { from, to, total })}</span>
      <span className="flex gap-2">
        {offset > 0 ? (
          <Link className="rounded border border-slate-300 px-2 py-1 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800" href={hrefFor(Math.max(0, offset - limit))}>
            {t('上一頁')}
          </Link>
        ) : null}
        {to < total ? (
          <Link className="rounded border border-slate-300 px-2 py-1 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800" href={hrefFor(offset + limit)}>
            {t('下一頁')}
          </Link>
        ) : null}
      </span>
    </nav>
  );
}

/** 搜尋框（GET 表單；保留其他篩選參數）。 */
export function SearchBox({
  t,
  action,
  q,
  keep,
  placeholder,
}: {
  t: TFn;
  action: string;
  q?: string;
  keep: Record<string, string | undefined>;
  placeholder: string;
}) {
  return (
    <form action={action} method="get" className="flex gap-2">
      {Object.entries(keep).map(([k, v]) => (v ? <input key={k} type="hidden" name={k} value={v} /> : null))}
      <input
        name="q"
        defaultValue={q}
        placeholder={placeholder}
        className="w-64 max-w-full rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
      />
      <button type="submit" className="rounded-md bg-teal-700 px-3 py-1 text-sm text-white hover:bg-teal-800">
        {t('搜尋')}
      </button>
    </form>
  );
}
