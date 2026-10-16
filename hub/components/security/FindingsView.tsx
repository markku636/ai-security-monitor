import { FindingsTable } from '@/components/security/FindingsTable';
import { statusText } from '@/components/security/Verdict';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow, Pager, SearchBox, toggled } from '@/components/ui/Filters';
import { sevLabel } from '@/components/ui/Severity';
import { getT } from '@/lib/i18n/server';
import { listFindings, parseFindingFilter, SEVERITIES, STATUSES, toFindingView, type FindingFilter } from '@/lib/queries/findings';
import { toQuery } from '@/lib/queries/params';

function href(base: string, f: FindingFilter, patch: Partial<FindingFilter>): string {
  const n = { ...f, ...patch };
  return (
    base +
    toQuery({
      agent_id: base === '/findings' ? n.agentId : undefined,
      tab: base === '/findings' ? undefined : 'findings',
      status: n.status,
      severity: n.severity,
      scanner: n.scanner,
      q: n.q,
      offset: n.offset || undefined,
    })
  );
}

/** 發現清單＋篩選＋批次處理（車隊頁與單一 agent 分頁共用）。 */
export async function FindingsView({ base, params, agentId }: { base: string; params: Record<string, string | string[] | undefined>; agentId?: string }) {
  const { t } = await getT();
  const f = { ...parseFindingFilter(params), ...(agentId ? { agentId } : {}) };
  const r = await listFindings(f);
  return (
    <div className="space-y-3">
      <div className="space-y-2 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        <FilterRow label={t('狀態')}>
          {STATUSES.map((s) => (
            <FilterChip key={s} href={href(base, f, { status: toggled(f.status, s), offset: 0 })} active={f.status.includes(s)}>
              {statusText(t, s)} <span className="opacity-70">{r.facets.status[s] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
        <FilterRow label={t('嚴重度')}>
          {SEVERITIES.map((s) => (
            <FilterChip key={s} href={href(base, f, { severity: toggled(f.severity, s), offset: 0 })} active={f.severity.includes(s)}>
              {sevLabel(t, s)} <span className="opacity-70">{r.facets.severity[s] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
        <SearchBox
          t={t}
          action={base}
          q={f.q}
          placeholder={t('標題、指標、規則或主機')}
          keep={{
            tab: agentId ? 'findings' : undefined,
            status: f.status.join(','),
            severity: f.severity.join(','),
            scanner: f.scanner.join(','),
          }}
        />
      </div>
      {r.items.length ? (
        <FindingsTable rows={r.items.map(toFindingView)} canWrite showHost={!agentId} />
      ) : (
        <EmptyState title={t('沒有符合條件的發現')} />
      )}
      <Pager t={t} total={r.total} limit={f.limit} offset={f.offset} hrefFor={(o) => href(base, f, { offset: o })} />
    </div>
  );
}
