import type { ReactNode } from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { requireViewer } from '@/lib/auth/require';
import { isOpenMode } from '@/lib/env';
import { getT } from '@/lib/i18n/server';
import { updateAvailable } from '@/lib/update';

export const dynamic = 'force-dynamic';

export default async function AppLayout({ children }: { children: ReactNode }) {
  const viewer = await requireViewer();
  const { t } = await getT();
  const items = [
    { href: '/', label: t('總覽') },
    { href: '/agents', label: t('代理程式') },
    ...(viewer.role === 'admin'
      ? [
          { href: '/connections', label: t('連線') },
          { href: '/findings', label: t('發現') },
          { href: '/vulns', label: t('漏洞與更新') },
          { href: '/hardening', label: t('系統硬化') },
          { href: '/traffic', label: t('流量') },
          { href: '/events', label: t('事件與當機') },
          { href: '/intel', label: t('威脅情資') },
          { href: '/actions', label: t('動作') },
          { href: '/ai', label: t('AI 分析') },
          { href: '/install', label: t('安裝代理程式') },
          { href: '/admin', label: t('管理') },
        ]
      : []),
  ];
  const update = viewer.role === 'admin' ? await updateAvailable() : null;
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <Sidebar t={t} items={items} viewer={viewer} openMode={isOpenMode()} />
      <main className="min-w-0 flex-1 p-4 md:p-6">
        {update ? (
          <p className="mb-4 rounded-lg border border-sky-300 bg-sky-50 px-3 py-2 text-sm text-sky-900 dark:border-sky-800 dark:bg-sky-950/40 dark:text-sky-200">
            {t('Security Hub {v} 已發佈。更新：docker compose pull && docker compose up -d', { v: update.latest })}
            {update.url ? (
              <a className="ml-2 underline" href={update.url} target="_blank" rel="noreferrer">
                {t('版本說明')}
              </a>
            ) : null}
          </p>
        ) : null}
        {children}
      </main>
    </div>
  );
}
