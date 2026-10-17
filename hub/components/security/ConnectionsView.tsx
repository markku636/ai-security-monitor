import { ConnectionsTable, GeoAttribution } from '@/components/security/ConnectionsTable';
import { directionLabel, verdictLabel } from '@/components/security/Verdict';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow, Pager, SearchBox, toggled } from '@/components/ui/Filters';
import { HostFilter } from '@/components/ui/HostFilter';
import { getT } from '@/lib/i18n/server';
import { DIRECTIONS, listConnections, parseConnectionFilter, VERDICTS, type ConnectionFilter } from '@/lib/queries/connections';
import { toQuery } from '@/lib/queries/params';

function href(base: string, f: ConnectionFilter, patch: Partial<ConnectionFilter>): string {
  const n = { ...f, ...patch };
  return (
    base +
    toQuery({
      agent_id: base === '/connections' ? n.agentId : undefined,
      tab: base === '/connections' ? undefined : 'connections',
      direction: n.direction,
      verdict: n.verdict,
      feed: n.feed,
      country: n.country,
      q: n.q,
      offset: n.offset || undefined,
    })
  );
}

/** 連線清單＋篩選（車隊頁與單一 agent 分頁共用）。 */
export async function ConnectionsView({ base, params, agentId }: { base: string; params: Record<string, string | string[] | undefined>; agentId?: string }) {
  const { t } = await getT();
  const f = { ...parseConnectionFilter(params), ...(agentId ? { agentId } : {}) };
  const r = await listConnections(f);
  const showHost = !agentId;
  return (
    <div className="space-y-3">
      <div className="space-y-2 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        {agentId ? null : (
          <HostFilter
            t={t}
            action={base}
            current={f.agentId}
            keep={{ direction: f.direction?.join(','), verdict: f.verdict?.join(','), feed: f.feed, country: f.country, q: f.q }}
          />
        )}
        <FilterRow label={t('判定')}>
          {VERDICTS.map((v) => (
            <FilterChip key={v} href={href(base, f, { verdict: toggled(f.verdict ?? [], v), offset: 0 })} active={!!f.verdict?.includes(v)}>
              {verdictLabel(t, v)} <span className="opacity-70">{r.facets.verdict[v] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
        <FilterRow label={t('方向')}>
          {DIRECTIONS.map((d) => (
            <FilterChip key={d} href={href(base, f, { direction: toggled(f.direction ?? [], d), offset: 0 })} active={!!f.direction?.includes(d)}>
              {directionLabel(t, d)} <span className="opacity-70">{r.facets.direction[d] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
        <div className="flex flex-wrap items-center gap-2">
          <SearchBox
            t={t}
            action={base}
            q={f.q}
            placeholder={t('IP、行程、組織或主機')}
            keep={{
              tab: agentId ? 'connections' : undefined,
              agent_id: agentId ? undefined : f.agentId,
              direction: f.direction?.join(','),
              verdict: f.verdict?.join(','),
              feed: f.feed,
              country: f.country,
            }}
          />
          {f.feed ? (
            <FilterChip href={href(base, f, { feed: undefined, offset: 0 })} active>
              {t('來源 {feed} ✕', { feed: f.feed })}
            </FilterChip>
          ) : null}
          {f.country ? (
            <FilterChip href={href(base, f, { country: undefined, offset: 0 })} active>
              {t('國家 {c} ✕', { c: f.country })}
            </FilterChip>
          ) : null}
        </div>
      </div>
      {r.items.length ? (
        <ConnectionsTable rows={r.items} t={t} showHost={showHost} />
      ) : (
        <EmptyState title={t('沒有符合條件的連線')}>{t('換個篩選條件，或等代理程式下一次回報快照。')}</EmptyState>
      )}
      <Pager t={t} total={r.total} limit={f.limit} offset={f.offset} hrefFor={(o) => href(base, f, { offset: o })} />
      <GeoAttribution t={t} />
    </div>
  );
}
