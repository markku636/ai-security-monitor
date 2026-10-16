import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ConnectionsView } from '@/components/security/ConnectionsView';
import { FindingsView } from '@/components/security/FindingsView';
import { DirectionBadge, VerdictChip } from '@/components/security/Verdict';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { Gauge } from '@/components/ui/Gauge';
import { ScorePill, SevCountsRow } from '@/components/ui/Severity';
import { requireAdmin } from '@/lib/auth/require';
import { bytes, since, utc } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import { agentReports, getAgent } from '@/lib/queries/agents';
import { riskyDestinations } from '@/lib/queries/connections';

export const dynamic = 'force-dynamic';

const TABS = ['overview', 'connections', 'findings', 'history'] as const;
type Tab = (typeof TABS)[number];

type Agent = NonNullable<Awaited<ReturnType<typeof getAgent>>>;

function tabLabel(t: TFn, tab: Tab): string {
  return { overview: t('概況'), connections: t('連線'), findings: t('發現'), history: t('報告紀錄') }[tab];
}

function StatusBadge({ t, a }: { t: TFn; a: Agent }) {
  if (a.status === 'online') return <Badge tone="ok">{t('線上')}</Badge>;
  if (a.status === 'stale') return <Badge tone="warn">{t('延遲')}</Badge>;
  return <Badge>{t('離線')}</Badge>;
}

async function OverviewTab({ t, a }: { t: TFn; a: Agent }) {
  const risky = await riskyDestinations(10, a.id);
  const rows: [string, string][] = [
    [t('系統'), [a.osName ?? a.osFamily, a.osVersion].filter(Boolean).join(' ')],
    [t('架構'), a.arch],
    [t('asa 版本'), a.version],
    [t('IP 位址'), a.ips.join(', ') || '—'],
    [t('執行身分'), a.elevated ? t('系統管理員') : t('一般使用者（部分資料可能缺漏）')],
    [t('執行方式'), a.serviceMode ? t('背景服務') : t('手動／排程')],
    [t('接受遠端動作'), a.acceptRemoteActions ? t('是') : t('否')],
    [t('首次出現'), utc(a.firstSeenAt)],
    [t('最後一份報告'), a.lastReportAt ? `${utc(a.lastReportAt)}（${since(a.lastReportAt, t)}）` : '—'],
    [t('最後一次快照'), a.lastSnapshotAt ? `${utc(a.lastSnapshotAt)}（${since(a.lastSnapshotAt, t)}）` : '—'],
  ];
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title={t('安全分數')}>
        <div className="flex flex-wrap justify-around gap-4">
          <Gauge score={a.score?.overall} label={t('總分')} size={104} />
          <Gauge score={a.score?.connections} label={t('連線')} size={76} />
          <Gauge score={a.score?.exposure} label={t('曝露')} size={76} />
          <Gauge score={a.score?.vulns} label={t('漏洞')} size={76} />
          <Gauge score={a.score?.hardening} label={t('硬化')} size={76} />
        </div>
        <div className="mt-4">
          <SevCountsRow counts={a.sevCounts} t={t} />
        </div>
      </Card>
      <Card title={t('主機資訊')}>
        <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1.5 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-slate-500">{k}</dt>
              <dd className="break-all">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>
      <Card title={t('看過的危險與可疑目的地')} className="xl:col-span-2">
        {risky.length ? (
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {risky.map((d) => (
              <li key={`${d.remoteIp}-${d.remotePort}-${d.direction}`} className="flex flex-wrap items-center gap-2 py-2">
                <VerdictChip verdict={d.worstVerdict} t={t} />
                <DirectionBadge direction={d.direction} t={t} />
                <span className="font-mono text-xs">
                  {d.remoteIp}:{d.remotePort}
                </span>
                <span className="text-xs text-slate-500">
                  {d.processName ?? '—'}
                  {d.country ? ` · ${d.country}` : ''}
                  {d.org ? ` · ${d.org}` : ''} · {t('看到 {n} 次，最後 {at}', { n: d.seenCount, at: since(d.lastSeenAt, t) })}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-slate-500">{t('這台主機還沒有連到過可疑或危險的位址。')}</p>
        )}
      </Card>
    </div>
  );
}

async function HistoryTab({ t, a }: { t: TFn; a: Agent }) {
  const reports = await agentReports(a.id, 50);
  if (!reports.length) return <EmptyState title={t('還沒有收到任何報告')} />;
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800">
          <tr>
            <th className="px-3 py-2">{t('完成時間')}</th>
            <th className="px-3 py-2">{t('總分')}</th>
            <th className="px-3 py-2">{t('發現')}</th>
            <th className="px-3 py-2">{t('新增／解決')}</th>
            <th className="px-3 py-2">{t('掃描器')}</th>
            <th className="px-3 py-2">{t('大小')}</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.id} className="border-b border-slate-100 last:border-0 dark:border-slate-800">
              <td className="px-3 py-2 whitespace-nowrap">
                {utc(r.finishedAt)}
                {r.partial ? (
                  <span className="ml-1">
                    <Badge tone="info">{t('部分資料')}</Badge>
                  </span>
                ) : null}
              </td>
              <td className="px-3 py-2">
                <ScorePill score={r.score.overall} />
              </td>
              <td className="px-3 py-2 tabular-nums">{r.findingsCount}</td>
              <td className="px-3 py-2 tabular-nums">
                +{r.newCount} / −{r.resolvedCount}
              </td>
              <td className="px-3 py-2 text-xs text-slate-500">{r.scannersRun.join(', ')}</td>
              <td className="px-3 py-2 text-xs text-slate-500">{bytes(r.payloadBytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function AgentPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  await requireAdmin();
  const { t } = await getT();
  const { id } = await params;
  const sp = await searchParams;
  const a = await getAgent(id);
  if (!a) notFound();
  const raw = Array.isArray(sp.tab) ? sp.tab[0] : sp.tab;
  const tab: Tab = (TABS as readonly string[]).includes(raw ?? '') ? (raw as Tab) : 'overview';
  const base = `/agents/${encodeURIComponent(a.id)}`;
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <Link href="/agents" className="text-sm text-slate-500 hover:underline">
          {t('← 代理程式')}
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold">{a.hostname}</h1>
          <StatusBadge t={t} a={a} />
          {a.partial ? <Badge tone="info">{t('部分資料')}</Badge> : null}
        </div>
        <p className="font-mono text-xs text-slate-500">{a.id}</p>
      </header>
      <nav className="flex gap-1 border-b border-slate-200 dark:border-slate-800">
        {TABS.map((k) => (
          <Link
            key={k}
            href={k === 'overview' ? base : `${base}?tab=${k}`}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${
              k === tab ? 'border-teal-600 font-medium text-teal-700 dark:text-teal-400' : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
            aria-current={k === tab ? 'page' : undefined}
          >
            {tabLabel(t, k)}
          </Link>
        ))}
      </nav>
      {tab === 'overview' ? <OverviewTab t={t} a={a} /> : null}
      {tab === 'connections' ? <ConnectionsView base={base} params={sp} agentId={a.id} /> : null}
      {tab === 'findings' ? <FindingsView base={base} params={sp} agentId={a.id} /> : null}
      {tab === 'history' ? <HistoryTab t={t} a={a} /> : null}
    </div>
  );
}
