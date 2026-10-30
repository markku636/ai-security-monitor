import Link from 'next/link';
import { AddTargetForm } from '@/components/webscan/AddTargetForm';
import { JobsTable } from '@/components/webscan/JobsTable';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Hint } from '@/components/ui/Hint';
import { SevCountsRow } from '@/components/ui/Severity';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import type { TargetListItem } from '@/lib/webscan/targets';
import { webscanView, type WebscanView } from '@/lib/webscan/view';

export const dynamic = 'force-dynamic';

/** 掃描端在線狀態一行：幾台、裝了哪些掃描器、部署連結。 */
function RunnerStrip({ runners, t }: { runners: WebscanView['runners']; t: TFn }) {
  const online = runners.filter((r) => r.online);
  const scanners = [...new Set(online.flatMap((r) => r.capabilities.map((c) => c.scanner)))];
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{t('掃描端')}</span>
        <Hint text={t('真正去連網站、執行掃描器的是另外一個容器（webscan runner），Hub 本身不會連到你的網站。')} />
        {online.length ? <Badge tone="ok">{t('{n} 台在線', { n: online.length })}</Badge> : <Badge tone="warn">{t('沒有掃描端在線')}</Badge>}
        <span className="text-slate-500">{scanners.join('、')}</span>
        <Link className="ml-auto text-teal-700 hover:underline dark:text-teal-400" href="/admin?tab=webscan">
          {t('部署與設定 →')}
        </Link>
      </div>
    </Card>
  );
}

function TargetRow({ x, t }: { x: TargetListItem; t: TFn }) {
  return (
    <tr className="border-b border-slate-100 last:border-0 dark:border-slate-800 [&_td]:px-3 [&_td]:py-2">
      <td>
        <Link className="font-mono text-teal-700 hover:underline dark:text-teal-400" href={`/web/${x.id}`}>
          {x.url}
        </Link>
        {x.name ? <div className="text-xs text-slate-500">{x.name}</div> : null}
      </td>
      <td className="whitespace-nowrap text-xs text-slate-500">{x.lastScanAt ? since(x.lastScanAt, t) : t('還沒掃過')}</td>
      <td>
        <SevCountsRow counts={x.counts} t={t} />
      </td>
    </tr>
  );
}

function TargetsTable({ targets, t }: { targets: TargetListItem[]; t: TFn }) {
  if (!targets.length) return <EmptyState title={t('還沒有掃描目標')}>{t('在上面輸入你的網站網址開始。')}</EmptyState>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap [&_th]:px-3 [&_th]:py-2">
          <tr>
            <th>{t('網址')}</th>
            <th>{t('最後掃描')}</th>
            <th>{t('未處理的問題')}</th>
          </tr>
        </thead>
        <tbody>
          {targets.map((x) => (
            <TargetRow key={x.id} x={x} t={t} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function WebScanPage() {
  await requireAdmin();
  const { t } = await getT();
  const v = await webscanView(getDb());
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('網站掃描')}</h1>
        <p className="text-sm text-slate-500">{t('新增網站後，開啟目標頁面即可手動檢查弱點、憑證與設定問題。')}</p>
      </header>
      <RunnerStrip runners={v.runners} t={t} />
      <Card title={t('新增目標')}>
        <AddTargetForm />
      </Card>
      <Card title={t('掃描目標')}>
        <TargetsTable targets={v.targets} t={t} />
      </Card>
      <Card title={t('最近的掃描')}>
        <JobsTable t={t} jobs={v.jobs} targets={new Map(v.targets.map((x) => [x.id, x.url]))} />
      </Card>
    </div>
  );
}
