import type { ReactNode } from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { requireViewer } from '@/lib/auth/require';
import { isOpenMode } from '@/lib/env';
import { getT } from '@/lib/i18n/server';

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
        ]
      : []),
  ];
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <Sidebar t={t} items={items} viewer={viewer} openMode={isOpenMode()} />
      <main className="min-w-0 flex-1 p-4 md:p-6">{children}</main>
    </div>
  );
}
