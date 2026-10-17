// 可點的表頭（純連結、不需要 client JS）：目前排序的欄位標 ▲／▼，其他欄位淡淡的 ↕；再點一次反向。
import Link from 'next/link';
import type { ReactNode } from 'react';

export function SortHeader({
  active,
  dir,
  href,
  children,
  title,
  className = 'px-3 py-2',
}: {
  active: boolean;
  dir: 'asc' | 'desc';
  href: string;
  children: ReactNode;
  title?: string;
  className?: string;
}) {
  return (
    <th className={className} title={title} aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <Link
        href={href}
        scroll={false}
        className={`inline-flex items-center gap-1 whitespace-nowrap hover:text-teal-700 dark:hover:text-teal-300 ${active ? 'text-slate-800 dark:text-slate-100' : ''}`}
      >
        {children}
        <span className={active ? '' : 'opacity-30'} aria-hidden>
          {active ? (dir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </Link>
    </th>
  );
}
