import type { Identity } from '@/lib/auth/access';
import type { TFn } from '@/lib/i18n/core';
import { LangSwitch, LogoutButton, ThemeToggle } from './Prefs';
import { SidebarNav, type NavGroup } from './SidebarNav';

export type { NavGroup } from './SidebarNav';

export function Sidebar({ t, groups, viewer, openMode }: { t: TFn; groups: NavGroup[]; viewer: Identity; openMode: boolean }) {
  return (
    <SidebarNav
      groups={groups}
      menuLabel={t('選單')}
      header={
        <div>
          <div className="text-base font-semibold tracking-tight">Security Hub</div>
          <div className="text-xs text-slate-400">ai-security-agent</div>
        </div>
      }
      footer={
        <div className="space-y-2 text-xs text-slate-400">
          <div>{openMode ? t('開放模式（僅本機）') : viewer.role === 'viewer' ? t('唯讀檢視') : t('管理員')}</div>
          <div className="flex flex-wrap gap-1">
            <LangSwitch />
            <ThemeToggle />
            {!openMode && viewer.via === 'session' ? <LogoutButton /> : null}
          </div>
        </div>
      }
    />
  );
}
