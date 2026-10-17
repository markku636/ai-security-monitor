import type { ReactNode } from 'react';
import { Sidebar, type NavGroup } from '@/components/layout/Sidebar';
import { listActions } from '@/lib/actions/store';
import { getDb } from '@/lib/db';
import { pendingCount as pendingEnrollCount } from '@/lib/enroll/store';
import { fleetSummary } from '@/lib/queries/agents';
import { requireViewer } from '@/lib/auth/require';
import { isOpenMode } from '@/lib/env';
import { getT } from '@/lib/i18n/server';
import { updateAvailable } from '@/lib/update';

export const dynamic = 'force-dynamic';

export default async function AppLayout({ children }: { children: ReactNode }) {
  const viewer = await requireViewer();
  const { t } = await getT();
  const admin = viewer.role === 'admin';
  // 待辦數字：嚴重＋高的未處理問題、待核准的封鎖；查不到不影響頁面
  const [urgent, pending, enrollPending] = admin
    ? await Promise.all([
        fleetSummary()
          .then((f) => f.severities.critical + f.severities.high)
          .catch(() => 0),
        listActions(getDb(), { status: ['pending'], limit: 1 })
          .then((r) => r.counts.pending ?? 0)
          .catch(() => 0),
        // 待核准的免金鑰加入申請
        Promise.resolve()
          .then(() => pendingEnrollCount(getDb()))
          .catch(() => 0),
      ])
    : [0, 0, 0];
  const groups: NavGroup[] = [
    {
      items: [
        { href: '/', label: t('總覽'), hint: t('所有主機的安全狀況'), icon: 'home' },
        { href: '/agents', label: t('主機'), hint: t('每台電腦的分數與狀態'), icon: 'hosts' },
      ],
    },
    ...(admin
      ? ([
          {
            title: t('要處理的事'),
            items: [
              { href: '/findings', label: t('待處理問題'), hint: t('掃描找到、需要你決定的項目'), icon: 'alert', badge: urgent, badgeTone: 'red' },
              { href: '/actions', label: t('封鎖審核'), hint: t('核准或拒絕封鎖 IP、關閉 port'), icon: 'block', badge: pending, badgeTone: 'amber' },
            ],
          },
          {
            title: t('網路'),
            items: [
              { href: '/connections', label: t('連線'), hint: t('誰連到哪裡、安全還是危險'), icon: 'network' },
              { href: '/traffic', label: t('流量'), hint: t('頻寬、哪台與哪個程式用最多、常連的目的地'), icon: 'traffic' },
              { href: '/intel', label: t('威脅情資'), hint: t('判斷危險用的黑名單來源'), icon: 'intel' },
            ],
          },
          {
            title: t('弱點'),
            items: [
              { href: '/vulns', label: t('漏洞與更新'), hint: t('過期系統、有漏洞的軟體'), icon: 'bug' },
              { href: '/hardening', label: t('安全設定'), hint: t('UAC、磁碟加密、SSH 等檢查'), icon: 'settingsCheck' },
            ],
          },
          {
            title: t('事件'),
            items: [
              { href: '/events', label: t('當機與事件'), hint: t('藍屏、程式當掉、暴力破解'), icon: 'event' },
              { href: '/mitre', label: t('攻擊手法與法規'), hint: t('MITRE ATT&CK 與 ISO、NIST、PCI、CIS 對應'), icon: 'matrix' },
            ],
          },
          {
            title: t('工具'),
            items: [
              { href: '/ai', label: t('AI 助手'), hint: t('用白話請 AI 解讀狀況'), icon: 'ai' },
              { href: '/install', label: t('新增主機'), hint: t('產生一行安裝指令、核准要加入的主機'), icon: 'add', badge: enrollPending, badgeTone: 'amber' },
              { href: '/admin', label: t('設定與金鑰'), hint: t('註冊金鑰、API token、稽核紀錄'), icon: 'key' },
            ],
          },
        ] satisfies NavGroup[])
      : []),
  ];
  const update = admin ? await updateAvailable() : null;
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <Sidebar t={t} groups={groups} viewer={viewer} openMode={isOpenMode()} />
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
