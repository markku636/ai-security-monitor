import { CrashTable, SecurityTable, crashKindLabel } from '@/components/security/EventViews';
import { IpRiskIcon } from '@/components/security/IpRisk';
import { SourceBadge } from '@/components/security/Verdict';
import { Card, Stat } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow } from '@/components/ui/Filters';
import { requireAdmin } from '@/lib/auth/require';
import { HostFilter } from '@/components/ui/HostFilter';
import { since } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import { cachedRisks } from '@/lib/ipintel/service';
import { bruteForceSources, crashCounts, recentCrashes, securityHits, topBugchecks } from '@/lib/queries/events';
import { clampInt, strParam, toQuery } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

const DAY_CHOICES = [7, 30, 90];
const KINDS = ['bugcheck', 'unexpected_shutdown', 'app_crash', 'service_fail', 'disk_error', 'whea_hardware', 'low_memory', 'kernel_panic', 'oom'];

export default async function EventsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const days = clampInt(sp, 'days', 30, 1, 90);
  const agentId = strParam(sp, 'agent_id', 64);
  const [counts, crashes, bugs, brute, sec] = await Promise.all([
    crashCounts(days, agentId),
    recentCrashes({ days, agentId, limit: 50 }),
    topBugchecks(days, 8, agentId),
    bruteForceSources(days, 10, agentId),
    securityHits({ days, agentId, minSeverity: 'medium', rules: undefined, limit: 50 }),
  ]);
  const shown = KINDS.filter((k) => counts[k]);
  const risks = await cachedRisks([...brute.map((b) => b.sourceIp), ...sec.map((h) => h.sourceIp)]);
  const empty = !crashes.length && !sec.length && !brute.length;
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">{t('當機與事件')}</h1>
          <p className="text-sm text-slate-500">{t('各主機回報的藍屏、非預期關機、程式當掉、硬體錯誤，以及暴力破解、新帳號、新服務等資安事件。')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <a href={`/ai${toQuery({ scope: 'events', agent_id: agentId })}`} className="rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950">{t('請 AI 分析當機原因')}</a>
          <FilterRow label={t('期間')}>
            {DAY_CHOICES.map((d) => (
            <FilterChip key={d} href={`/events${toQuery({ days: d, agent_id: agentId })}`} active={d === days}>
              {t('{n} 天', { n: d })}
            </FilterChip>
            ))}
          </FilterRow>
        </div>
      </header>
      <HostFilter t={t} action="/events" current={agentId} keep={{ days }} />
      {empty ? (
        <EmptyState title={t('這段期間沒有當機或資安事件')}>{t('主機的掃描會帶上近 7 天的事件摘要；以系統管理員執行才讀得到 Security 記錄。')}</EmptyState>
      ) : null}
      {shown.length ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {shown.map((k) => (
            <Stat key={k} label={crashKindLabel(t, k)} value={counts[k].count} hint={t('{n} 台主機', { n: counts[k].hosts })} />
          ))}
        </div>
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        {bugs.length ? (
          <Card title={t('最常見的藍屏')}>
            <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
              {bugs.map((b) => (
                <li key={b.code ?? '?'} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
                  <span>
                    <span className="font-mono text-xs">{b.code}</span> <span className="font-medium">{b.name ?? ''}</span>
                  </span>
                  <span className="text-xs text-slate-500">
                    {t('{n} 次、{h} 台主機，最近 {at}', { n: b.count, h: b.hosts, at: since(b.last, t) })}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        ) : null}
        {brute.length ? (
          <Card title={t('暴力破解來源')}>
            <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
              {brute.map((b) => (
                <li key={b.sourceIp} className="flex flex-col gap-1 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1">
                      <IpRiskIcon t={t} risk={risks[b.sourceIp]} />
                      <a className="font-mono text-xs hover:underline" href={`/ip/${encodeURIComponent(b.sourceIp)}`}>
                        {b.sourceIp}
                      </a>
                    </span>
                    <span className="text-xs text-slate-500">
                      {t('{n} 次失敗登入、{h} 台主機，最近 {at}', { n: b.attempts, h: b.hosts, at: since(b.last, t) })}
                    </span>
                  </div>
                  {b.intel.length ? (
                    <div className="flex flex-wrap gap-1">
                      {b.intel.map((x, i) => (
                        <SourceBadge key={i} r={{ type: 'intel_hit', ...x }} t={t} />
                      ))}
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          </Card>
        ) : null}
      </div>
      {sec.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('資安事件（中以上）')}</h2>
          <SecurityTable t={t} rows={sec} risks={risks} />
        </section>
      ) : null}
      {crashes.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('最近的當機與錯誤')}</h2>
          <CrashTable t={t} rows={crashes} />
        </section>
      ) : null}
    </div>
  );
}
