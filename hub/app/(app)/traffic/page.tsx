import { GeoAttribution } from '@/components/security/ConnectionsTable';
import { DestinationTable, ProcessTable } from '@/components/security/EventViews';
import { EmptyState } from '@/components/ui/EmptyState';
import { requireAdmin } from '@/lib/auth/require';
import { HostFilter } from '@/components/ui/HostFilter';
import { getT } from '@/lib/i18n/server';
import { cachedRisks } from '@/lib/ipintel/service';
import { FleetTrafficSection, RangeChips } from '@/components/metrics/MetricsViews';
import { hostTrafficRanking, parseRange, type Range } from '@/lib/queries/metrics';
import { clampInt, strParam, toQuery } from '@/lib/queries/params';
import { newDestinations, processActivity, topDestinations } from '@/lib/queries/traffic';

/** 舊連結的 days=1/7/30 → 期間。 */
function rangeOf(sp: Record<string, string | string[] | undefined>): Range {
  if (sp.range) return parseRange(sp);
  const d = clampInt(sp, 'days', 0, 0, 90);
  return d >= 30 ? '30d' : d >= 7 ? '7d' : '24h';
}

export const dynamic = 'force-dynamic';

export default async function TrafficPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const range = rangeOf(sp);
  const days = { '1h': 1, '24h': 1, '7d': 7, '30d': 30 }[range];
  const agentId = strParam(sp, 'agent_id', 64);
  const [risky, fresh, top, procs, ranking] = await Promise.all([
    topDestinations({ days, agentId, risky: true, limit: 30 }),
    newDestinations(24, 30, agentId),
    topDestinations({ days, agentId, limit: 50 }),
    processActivity(agentId, 20),
    agentId ? Promise.resolve([]) : hostTrafficRanking(15),
  ]);
  const risks = await cachedRisks([...risky, ...fresh, ...top].map((d) => d.remoteIp));
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">{t('流量')}</h1>
          <p className="text-sm text-slate-500">
            {t('各主機每分鐘回報的上傳／下載量（頻寬、各網路介面、各程式），加上連線快照彙整的目的地與各行程連線數。逐封包分析請在主機上用 ai-security-monitor traffic analyze。')}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <a href={`/ai${toQuery({ scope: 'traffic', agent_id: agentId })}`} className="rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950">{t('請 AI 解讀流量')}</a>
          <RangeChips t={t} base="/traffic" range={range} keep={{ agent_id: agentId }} />
        </div>
      </header>
      <HostFilter t={t} action="/traffic" current={agentId} keep={{ range }} />
      <FleetTrafficSection t={t} range={range} agentId={agentId} ranking={ranking} />
      {!top.length ? <EmptyState title={t('還沒有流量資料')}>{t('主機執行 ai-security-monitor watch 後每分鐘會回報連線快照。')}</EmptyState> : null}
      {risky.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('危險與可疑目的地')}</h2>
          <DestinationTable t={t} rows={risky} risks={risks} />
        </section>
      ) : null}
      {procs.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('各行程目前的連線')}</h2>
          <ProcessTable t={t} rows={procs} />
        </section>
      ) : null}
      {fresh.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('24 小時內新出現的目的地')}</h2>
          <DestinationTable t={t} rows={fresh.map((d) => ({ ...d, asn: null, lastSeenAt: d.firstSeenAt, seenCount: 1 }))} risks={risks} />
        </section>
      ) : null}
      {top.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('最常連的目的地')}</h2>
          <DestinationTable t={t} rows={top} risks={risks} />
        </section>
      ) : null}
      <GeoAttribution t={t} />
    </div>
  );
}
