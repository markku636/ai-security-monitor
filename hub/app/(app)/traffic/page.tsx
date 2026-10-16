import { GeoAttribution } from '@/components/security/ConnectionsTable';
import { DestinationTable, ProcessTable } from '@/components/security/EventViews';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow } from '@/components/ui/Filters';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import { clampInt } from '@/lib/queries/params';
import { newDestinations, processActivity, topDestinations } from '@/lib/queries/traffic';

export const dynamic = 'force-dynamic';

export default async function TrafficPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const days = clampInt(sp, 'days', 7, 1, 90);
  const [risky, fresh, top, procs] = await Promise.all([
    topDestinations({ days, risky: true, limit: 30 }),
    newDestinations(24, 30),
    topDestinations({ days, limit: 50 }),
    processActivity(undefined, 20),
  ]);
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">{t('流量')}</h1>
          <p className="text-sm text-slate-500">
            {t('依各主機的連線快照彙整：最常連的目的地、新出現的目的地、各行程的連線數。逐封包分析請在主機上用 asa traffic analyze。')}
          </p>
        </div>
        <FilterRow label={t('期間')}>
          {[1, 7, 30].map((d) => (
            <FilterChip key={d} href={`/traffic?days=${d}`} active={d === days}>
              {t('{n} 天', { n: d })}
            </FilterChip>
          ))}
        </FilterRow>
      </header>
      {!top.length ? <EmptyState title={t('還沒有流量資料')}>{t('代理程式執行 asa watch 後每分鐘會回報連線快照。')}</EmptyState> : null}
      {risky.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('危險與可疑目的地')}</h2>
          <DestinationTable t={t} rows={risky} />
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
          <DestinationTable t={t} rows={fresh.map((d) => ({ ...d, asn: null, lastSeenAt: d.firstSeenAt, seenCount: 1 }))} />
        </section>
      ) : null}
      {top.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('最常連的目的地')}</h2>
          <DestinationTable t={t} rows={top} />
        </section>
      ) : null}
      <GeoAttribution t={t} />
    </div>
  );
}
