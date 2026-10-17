import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ConnectionsView } from '@/components/security/ConnectionsView';
import { FindingsView } from '@/components/security/FindingsView';
import { IpLink } from '@/components/security/IpLink';
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
import { latestSummary, recentCrashes, securityHits } from '@/lib/queries/events';
import { newDestinations, processActivity, topDestinations } from '@/lib/queries/traffic';
import { CrashTable, DestinationTable, ProcessTable, SecurityTable } from '@/components/security/EventViews';
import { AppHitsTable, HardeningTable, OsvTable, ScoreTrend, SupportBadge } from '@/components/security/PostureViews';
import { agentHardening, agentVuln, type VulnSummary } from '@/lib/queries/posture';

export const dynamic = 'force-dynamic';

const TABS = ['overview', 'connections', 'findings', 'vulns', 'hardening', 'events', 'traffic', 'history'] as const;
type Tab = (typeof TABS)[number];

type Agent = NonNullable<Awaited<ReturnType<typeof getAgent>>>;

function tabLabel(t: TFn, tab: Tab): string {
  return {
    overview: t('概況'),
    connections: t('連線'),
    findings: t('問題'),
    vulns: t('漏洞與更新'),
    hardening: t('安全設定'),
    events: t('當機與事件'),
    traffic: t('流量'),
    history: t('報告紀錄'),
  }[tab];
}

function StatusBadge({ t, a }: { t: TFn; a: Agent }) {
  if (a.status === 'online') return <Badge tone="ok">{t('線上')}</Badge>;
  if (a.status === 'stale') return <Badge tone="warn">{t('延遲')}</Badge>;
  return <Badge>{t('離線')}</Badge>;
}

async function OverviewTab({ t, a }: { t: TFn; a: Agent }) {
  const [risky, history] = await Promise.all([riskyDestinations(10, a.id), agentReports(a.id, 60)]);
  const trend = history
    .slice()
    .reverse()
    .map((r) => ({
      at: r.finishedAt,
      overall: r.score.overall,
      vulns: r.scannersRun.includes('vuln') ? r.score.vulns : undefined,
      hardening: r.scannersRun.includes('hardening') ? r.score.hardening : undefined,
    }));
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
      <Card title={t('分數趨勢（最近 {n} 份報告）', { n: trend.length })} className="xl:col-span-2">
        <ScoreTrend t={t} points={trend} />
      </Card>
      <Card title={t('看過的危險與可疑目的地')} className="xl:col-span-2">
        {risky.length ? (
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {risky.map((d) => (
              <li key={`${d.remoteIp}-${d.remotePort}-${d.direction}`} className="flex flex-wrap items-center gap-2 py-2">
                <VerdictChip verdict={d.worstVerdict} t={t} />
                <DirectionBadge direction={d.direction} t={t} />
                <IpLink ip={d.remoteIp} className="font-mono text-xs">
                  {d.remoteIp}:{d.remotePort}
                </IpLink>
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

async function EventsTab({ t, a }: { t: TFn; a: Agent }) {
  const [crashes, sec, summary] = await Promise.all([
    recentCrashes({ agentId: a.id, days: 90, limit: 100 }),
    securityHits({ agentId: a.id, days: 90, limit: 100 }),
    latestSummary(a.id, 'events'),
  ]);
  const s = (summary?.summary ?? {}) as {
    needs_admin?: string[];
    top_error_sources?: { provider: string; event_id: number; count: number; sample?: string }[];
    counts_by_level?: Record<string, number>;
  };
  if (!crashes.length && !sec.length && !summary) {
    return <EmptyState title={t('還沒有事件資料')}>{t('這台主機的 asa 掃描會帶上近 7 天的事件摘要。')}</EmptyState>;
  }
  return (
    <div className="space-y-4">
      {s.needs_admin?.length ? (
        <p className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          {t('需要系統管理員權限才能讀取：{what}', { what: s.needs_admin.join('、') })}
        </p>
      ) : null}
      {sec.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('資安事件')}</h2>
          <SecurityTable t={t} rows={sec} showHost={false} />
        </section>
      ) : null}
      {crashes.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('當機與錯誤')}</h2>
          <CrashTable t={t} rows={crashes} showHost={false} />
        </section>
      ) : null}
      {s.top_error_sources?.length ? (
        <Card title={t('最常出現的錯誤（最近一次掃描）')}>
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {s.top_error_sources.map((e) => (
              <li key={`${e.provider}-${e.event_id}`} className="py-1.5">
                <span className="tabular-nums font-medium">{e.count}×</span> <span>{e.provider}</span>{' '}
                <span className="font-mono text-xs text-slate-500">#{e.event_id}</span>
                {e.sample ? <div className="truncate text-xs text-slate-500">{e.sample}</div> : null}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}

async function TrafficTab({ t, a }: { t: TFn; a: Agent }) {
  const [top, fresh, procs] = await Promise.all([
    topDestinations({ agentId: a.id, days: 7, limit: 50 }),
    newDestinations(24, 30, a.id),
    processActivity(a.id, 20),
  ]);
  if (!top.length && !procs.length) {
    return <EmptyState title={t('還沒有流量資料')}>{t('代理程式執行 asa watch 後每分鐘會回報連線快照。')}</EmptyState>;
  }
  return (
    <div className="space-y-4">
      {procs.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('各行程目前的連線')}</h2>
          <ProcessTable t={t} rows={procs} showHosts={false} />
        </section>
      ) : null}
      {fresh.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('24 小時內新出現的目的地')}</h2>
          <DestinationTable t={t} rows={fresh.map((d) => ({ ...d, asn: null, lastSeenAt: d.firstSeenAt, seenCount: 1 }))} showHost={false} />
        </section>
      ) : null}
      {top.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('最常連的目的地（7 天）')}</h2>
          <DestinationTable t={t} rows={top} showHost={false} />
        </section>
      ) : null}
    </div>
  );
}

async function VulnsTab({ t, a }: { t: TFn; a: Agent }) {
  const v = await agentVuln(a.id);
  if (!v) return <EmptyState title={t('還沒有漏洞資料')}>{t('代理程式執行 asa scan 或 asa watch 時會一併回報（需要 asa 0.1 以上）。')}</EmptyState>;
  const s = v.summary;
  const eco = Object.entries(s.by_ecosystem)
    .map(([k, n]) => `${k} ${n}`)
    .join(' · ');
  const support = s.support;
  const left = support?.days_left != null && support.days_left >= 0 ? ` · ${t('剩 {n} 天', { n: support.days_left })}` : '';
  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title={t('作業系統')}>
          <div className="text-sm">{[s.os.name, s.os.version].filter(Boolean).join(' ') || '—'}</div>
          {support ? (
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
              <SupportBadge t={t} status={support.status} />
              <span className="text-slate-500">
                {support.product}
                {support.eol ? ` · ${support.eol}` : ''}
                {left}
              </span>
            </div>
          ) : null}
          {support?.note ? <p className="mt-2 text-xs text-slate-500">{support.note}</p> : null}
        </Card>
        <Card title={t('更新')}>
          <PatchInfo t={t} s={s} />
        </Card>
        <Card title={t('已安裝軟體')}>
          <div className="text-2xl font-semibold tabular-nums">{s.packages}</div>
          <div className="text-xs text-slate-500">{eco || '—'}</div>
          <div className="mt-1 text-xs text-slate-500">{t('回報時間 {when}', { when: since(v.at, t) })}</div>
        </Card>
      </div>
      {s.kev_count > 0 ? (
        <p className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          {t('有 {n} 個 CVE 在 CISA KEV（已被用於攻擊），請優先更新。', { n: s.kev_count })}
        </p>
      ) : null}
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('有已知漏洞或已停止支援的軟體')}</h2>
        {s.app_hits.length ? <AppHitsTable t={t} hits={s.app_hits} /> : <p className="text-sm text-slate-500">{t('內建規則沒有比對到已知漏洞版本的軟體。')}</p>}
      </section>
      {s.osv ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">
            {t('OSV（{eco}）：查了 {q} 個套件，{n} 個有已公告漏洞', { eco: s.osv.ecosystem, q: s.osv.queried, n: s.osv.packages.length })}
          </h2>
          {s.osv.packages.length ? <OsvTable t={t} osv={s.osv} /> : null}
        </section>
      ) : null}
      {s.notes.length ? (
        <ul className="list-disc pl-5 text-xs text-slate-500">
          {s.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function PatchInfo({ t, s }: { t: TFn; s: VulnSummary }) {
  if (!s.last_patch && !s.pending_updates) return <p className="text-sm text-slate-500">—</p>;
  const stale = (s.last_patch?.days ?? 0) > 45;
  return (
    <div className="space-y-1 text-sm">
      {s.last_patch ? (
        <p className={stale ? 'font-semibold text-amber-700 dark:text-amber-400' : ''}>
          {t('最近一次：{id}（{date}，{days} 天前）', { id: s.last_patch.id, date: s.last_patch.date, days: s.last_patch.days })}
        </p>
      ) : null}
      {s.pending_updates ? <p>{t('待安裝 {total} 個，其中安全性 {sec} 個', { total: s.pending_updates.total, sec: s.pending_updates.security })}</p> : null}
    </div>
  );
}

const RESULT_ORDER = { fail: 0, error: 1, pass: 2, not_applicable: 3 } as const;
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

async function HardeningTab({ t, a, sp }: { t: TFn; a: Agent; sp: Record<string, string | string[] | undefined> }) {
  const h = await agentHardening(a.id);
  if (!h) return <EmptyState title={t('還沒有硬化檢查資料')}>{t('代理程式執行 asa scan 或 asa watch 時會一併回報；本機可用 asa harden 先看結果。')}</EmptyState>;
  const s = h.summary;
  const all = (Array.isArray(sp.show) ? sp.show[0] : sp.show) === 'all';
  const rows = s.results
    .filter((o) => all || o.result === 'fail' || o.result === 'error')
    .sort((x, y) => RESULT_ORDER[x.result] - RESULT_ORDER[y.result] || SEV_ORDER[x.severity] - SEV_ORDER[y.severity]);
  const base = `/agents/${encodeURIComponent(a.id)}?tab=hardening`;
  const on = 'border-teal-600 text-teal-700 dark:text-teal-300';
  const off = 'border-slate-300 dark:border-slate-700';
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-6">
        <Gauge score={s.score ?? null} label={t('硬化')} size={96} />
        <div className="text-sm">
          <div>{t('通過 {pass} · 未通過 {fail} · 不適用 {na} · 錯誤 {error}', { pass: s.pass, fail: s.fail, na: s.na, error: s.error })}</div>
          <div className="text-xs text-slate-500">{t('回報時間 {when}', { when: since(h.at, t) })}</div>
          {s.needs_admin.length ? <div className="mt-1 text-xs text-slate-500">{t('{n} 項需要管理員權限', { n: s.needs_admin.length })}</div> : null}
        </div>
        <div className="ml-auto flex gap-2 text-xs">
          <Link className={`rounded-md border px-2 py-1 ${all ? off : on}`} href={base}>
            {t('只看未通過')}
          </Link>
          <Link className={`rounded-md border px-2 py-1 ${all ? on : off}`} href={`${base}&show=all`}>
            {t('全部 {n} 項', { n: s.results.length })}
          </Link>
        </div>
      </div>
      {rows.length ? <HardeningTable t={t} rows={rows} /> : <p className="text-sm text-slate-500">{t('全部通過。')}</p>}
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
            <th className="px-3 py-2">{t('問題')}</th>
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
          <Link
            href={`/ai?scope=agent&agent_id=${encodeURIComponent(a.id)}`}
            className="ml-auto rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950"
          >
            {t('請 AI 檢查這台主機')}
          </Link>
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
      {tab === 'vulns' ? <VulnsTab t={t} a={a} /> : null}
      {tab === 'hardening' ? <HardeningTab t={t} a={a} sp={sp} /> : null}
      {tab === 'events' ? <EventsTab t={t} a={a} /> : null}
      {tab === 'traffic' ? <TrafficTab t={t} a={a} /> : null}
      {tab === 'history' ? <HistoryTab t={t} a={a} /> : null}
    </div>
  );
}
