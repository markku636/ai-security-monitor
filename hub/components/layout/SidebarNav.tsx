'use client';

// 分組選單：圖示＋名稱＋一行說明、目前頁面高亮、待辦數字；手機版可收合。
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, type ReactNode } from 'react';
import { NavIcon, type IconName } from './NavIcons';

export interface NavItem {
  href: string;
  label: string;
  hint: string;
  icon: IconName;
  /** 待辦數字（0 不顯示）。 */
  badge?: number;
  badgeTone?: 'red' | 'amber';
}

export interface NavGroup {
  title?: string;
  items: NavItem[];
}

function active(path: string, href: string): boolean {
  return href === '/' ? path === '/' : path === href || path.startsWith(`${href}/`);
}

export function SidebarNav({ groups, menuLabel, header, footer }: { groups: NavGroup[]; menuLabel: string; header: ReactNode; footer: ReactNode }) {
  const path = usePathname() ?? '/';
  const [open, setOpen] = useState(false);
  const current = groups.flatMap((g) => g.items).find((i) => active(path, i.href));
  return (
    <aside className="w-full bg-slate-900 text-slate-100 print:hidden md:sticky md:top-0 md:flex md:h-screen md:w-64 md:shrink-0 md:flex-col">
      <div className="flex items-center justify-between px-4 py-3 md:block md:py-4">
        {header}
        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 md:hidden"
          aria-expanded={open}
          aria-controls="asa-nav"
          onClick={() => setOpen((v) => !v)}
        >
          <NavIcon name={open ? 'close' : 'menu'} className="h-4 w-4" />
          {current?.label ?? menuLabel}
        </button>
      </div>
      <nav id="asa-nav" className={`${open ? 'block' : 'hidden'} overflow-y-auto px-2 pb-3 md:block md:flex-1`} aria-label={menuLabel}>
        {groups.map((g, gi) => (
          <div key={gi} className={gi ? 'mt-3' : ''}>
            {g.title ? <div className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{g.title}</div> : null}
            <ul className="space-y-0.5">
              {g.items.map((it) => {
                const on = active(path, it.href);
                return (
                  <li key={it.href}>
                    <Link
                      href={it.href}
                      onClick={() => setOpen(false)}
                      aria-current={on ? 'page' : undefined}
                      className={`group flex items-start gap-3 rounded-md px-3 py-1.5 ${on ? 'bg-teal-600/20 text-white ring-1 ring-inset ring-teal-500/40' : 'text-slate-300 hover:bg-slate-800 hover:text-white'}`}
                    >
                      <span className={`mt-0.5 ${on ? 'text-teal-300' : 'text-slate-400 group-hover:text-slate-200'}`}>
                        <NavIcon name={it.icon} />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2 text-sm font-medium">
                          {it.label}
                          {it.badge ? (
                            <span
                              className={`ml-auto rounded-full px-1.5 text-[11px] font-semibold tabular-nums ${it.badgeTone === 'amber' ? 'bg-amber-500 text-amber-950' : 'bg-red-600 text-white'}`}
                            >
                              {it.badge > 99 ? '99+' : it.badge}
                            </span>
                          ) : null}
                        </span>
                        <span className={`block text-xs leading-snug ${on ? 'text-teal-100/80' : 'text-slate-500 group-hover:text-slate-400'}`}>{it.hint}</span>
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className={`${open ? 'block' : 'hidden'} border-t border-slate-800 px-4 py-3 md:block`}>{footer}</div>
    </aside>
  );
}
