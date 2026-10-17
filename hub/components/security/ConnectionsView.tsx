import { ConnectionsTable, GeoAttribution } from '@/components/security/ConnectionsTable';
import { directionLabel, verdictLabel } from '@/components/security/Verdict';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow, Pager, SearchBox, toggled } from '@/components/ui/Filters';
import { HostFilter } from '@/components/ui/HostFilter';
import { getT } from '@/lib/i18n/server';
import { DIRECTIONS, listConnections, parseConnectionFilter, PROTOS, REASON_KINDS, VERDICTS, type ConnectionFilter, type ConnSortKey } from '@/lib/queries/connections';
import { cachedRisks } from '@/lib/ipintel/service';
import { ipNoteMap } from '@/lib/queries/ipnotes';
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
      proto: n.proto,
      state: n.state,
      reason: n.reason,
      feed: n.feed,
      country: n.country,
      process: n.process,
      port: n.port,
      public: n.publicOnly ? '1' : undefined,
      q: n.q,
      sort: n.sort,
      dir: n.dir,
      offset: n.offset || undefined,
    })
  );
}

/** 篩選以外要保留的參數（給 GET 表單的 hidden 欄位）。 */
function keepOf(f: ConnectionFilter, agentId: string | undefined, omit: string[] = []): Record<string, string | undefined> {
  const all: Record<string, string | undefined> = {
    tab: agentId ? 'connections' : undefined,
    agent_id: agentId ? undefined : f.agentId,
    direction: f.direction?.join(','),
    verdict: f.verdict?.join(','),
    proto: f.proto?.join(','),
    state: f.state?.join(','),
    reason: f.reason?.join(','),
    feed: f.feed,
    country: f.country,
    process: f.process,
    port: f.port !== undefined ? String(f.port) : undefined,
    public: f.publicOnly ? '1' : undefined,
    q: f.q,
    sort: f.sort,
    dir: f.dir,
  };
  for (const k of omit) delete all[k];
  return all;
}

/** 連線清單＋篩選（車隊頁與單一 agent 分頁共用）。 */
export async function ConnectionsView({ base, params, agentId }: { base: string; params: Record<string, string | string[] | undefined>; agentId?: string }) {
  const { t } = await getT();
  const f = { ...parseConnectionFilter(params), ...(agentId ? { agentId } : {}) };
  const r = await listConnections(f);
  const ips = r.items.map((c) => c.remoteIp);
  const [noteMap, risks] = await Promise.all([ipNoteMap(ips), cachedRisks(ips)]);
  const notes = Object.fromEntries(noteMap);
  const showHost = !agentId;
  return (
    <div className="space-y-3">
      <div className="space-y-2 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        {agentId ? null : (
          <HostFilter
            t={t}
            action={base}
            current={f.agentId}
            keep={keepOf(f, agentId, ['agent_id', 'tab'])}
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
        <FilterRow label={t('協定')}>
          {PROTOS.map((p) => (
            <FilterChip key={p} href={href(base, f, { proto: toggled(f.proto ?? [], p), offset: 0 })} active={!!f.proto?.includes(p)}>
              {p.toUpperCase()} <span className="opacity-70">{r.facets.proto[p] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
        {Object.keys(r.facets.state).length ? (
          <FilterRow label={t('狀態')}>
            {Object.entries(r.facets.state).map(([st, n]) => (
              <FilterChip key={st} href={href(base, f, { state: toggled(f.state ?? [], st), offset: 0 })} active={!!f.state?.includes(st)}>
                {st || '—'} <span className="opacity-70">{n}</span>
              </FilterChip>
            ))}
          </FilterRow>
        ) : null}
        <FilterRow label={t('理由')}>
          {REASON_KINDS.map((k) => (
            <FilterChip key={k} href={href(base, f, { reason: toggled(f.reason ?? [], k), offset: 0 })} active={!!f.reason?.includes(k)}>
              {{ intel: t('情資'), behavior: t('行為'), none: t('沒有理由') }[k]} <span className="opacity-70">{r.facets.reason[k] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
        <form action={base} method="get" className="flex flex-wrap items-end gap-2 text-xs text-slate-500">
          {Object.entries(keepOf(f, agentId, ['process', 'port', 'public'])).map(([k, v]) => (v ? <input key={k} type="hidden" name={k} value={v} /> : null))}
          <label className="flex flex-col gap-1">
            {t('程式')}
            <input
              name="process"
              list="conn-processes"
              defaultValue={f.process ?? ''}
              placeholder={t('例：chrome.exe')}
              className="w-44 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
            />
            <datalist id="conn-processes">
              {r.facets.process.map((p) => (
                <option key={p.name} value={p.name}>
                  {t('{n} 條', { n: p.n })}
                </option>
              ))}
            </datalist>
          </label>
          <label className="flex flex-col gap-1">
            port
            <input
              name="port"
              inputMode="numeric"
              pattern="[0-9]*"
              defaultValue={f.port ?? ''}
              placeholder="443"
              className="w-24 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
            />
          </label>
          <label className="flex items-center gap-1 pb-1.5" title={t('只看連到網際網路上的位址（排除區網、本機、保留位址）')}>
            <input type="checkbox" name="public" value="1" defaultChecked={f.publicOnly} className="accent-teal-700" />
            {t('只看公網位址')}
          </label>
          <button type="submit" className="rounded-md bg-teal-700 px-3 py-1 text-sm text-white hover:bg-teal-800">
            {t('套用')}
          </button>
          <a href={base + (agentId ? '?tab=connections' : '')} className="pb-1.5 text-teal-700 hover:underline dark:text-teal-400">
            {t('清除篩選')}
          </a>
        </form>
        <div className="flex flex-wrap items-center gap-2">
          <SearchBox
            t={t}
            action={base}
            q={f.q}
            placeholder={t('IP、行程、組織或主機')}
            keep={keepOf(f, agentId, ['q'])}
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
        <ConnectionsTable
          rows={r.items}
          t={t}
          showHost={showHost}
          notes={notes}
          risks={risks}
          sort={{ key: f.sort ?? 'verdict', dir: f.dir ?? 'asc' }}
          sortHref={(k: ConnSortKey) =>
            href(base, f, { sort: k, dir: (f.sort ?? 'verdict') === k && (f.dir ?? 'asc') === 'asc' ? 'desc' : 'asc', offset: 0 })
          }
        />
      ) : (
        <EmptyState title={t('沒有符合條件的連線')}>{t('換個篩選條件，或等主機下一次回報快照。')}</EmptyState>
      )}
      <Pager t={t} total={r.total} limit={f.limit} offset={f.offset} hrefFor={(o) => href(base, f, { offset: o })} />
      <GeoAttribution t={t} />
    </div>
  );
}
