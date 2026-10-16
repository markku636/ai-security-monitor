import Link from 'next/link';
import type { Identity } from '@/lib/auth/access';
import type { TFn } from '@/lib/i18n/core';
import { LangSwitch, LogoutButton, ThemeToggle } from './Prefs';

export interface NavItem {
  href: string;
  label: string;
}

export function Sidebar({ t, items, viewer, openMode }: { t: TFn; items: NavItem[]; viewer: Identity; openMode: boolean }) {
  return (
    <aside className="flex w-full flex-col bg-slate-900 text-slate-100 md:min-h-screen md:w-56">
      <div className="px-4 py-4">
        <div className="text-base font-semibold tracking-tight">Security Hub</div>
        <div className="text-xs text-slate-400">ai-security-agent</div>
      </div>
      <nav className="flex flex-row flex-wrap gap-1 px-2 md:flex-col">
        {items.map((it) => (
          <Link
            key={it.href}
            href={it.href}
            className="rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white"
          >
            {it.label}
          </Link>
        ))}
      </nav>
      <div className="mt-auto space-y-2 px-4 py-4 text-xs text-slate-400">
        <div>
          {openMode ? t('開放模式（僅本機）') : viewer.role === 'viewer' ? t('唯讀檢視') : t('管理員')}
        </div>
        <div className="flex flex-wrap gap-1">
          <LangSwitch />
          <ThemeToggle />
          {!openMode && viewer.via === 'session' ? <LogoutButton /> : null}
        </div>
      </div>
    </aside>
  );
}
