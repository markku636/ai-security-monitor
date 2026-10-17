import { FindingsTable } from '@/components/security/FindingsTable';
import { statusText } from '@/components/security/Verdict';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow, Pager, SearchBox, toggled } from '@/components/ui/Filters';
import { HostFilter } from '@/components/ui/HostFilter';
import { sevLabel } from '@/components/ui/Severity';
import { controlLabel, techniqueLabel } from '@/components/security/AttackTags';
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
      technique: n.technique,
      control: n.control,
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
        {agentId ? null : (
          <HostFilter
            t={t}
            action={base}
            current={f.agentId}
            keep={{ status: f.status.join(','), severity: f.severity.join(','), scanner: f.scanner.join(','), q: f.q, technique: f.technique, control: f.control }}
          />
        )}
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
        {f.technique || f.control ? (
          <FilterRow label={t('對應')}>
            {f.technique ? (
              <FilterChip href={href(base, f, { technique: undefined, offset: 0 })} active>
                MITRE {f.technique} {techniqueLabel(f.technique, t)} ✕
              </FilterChip>
            ) : null}
            {f.control ? (
              <FilterChip href={href(base, f, { control: undefined, offset: 0 })} active>
                {f.control.includes(':') ? controlLabel(f.control, t) : f.control} ✕
              </FilterChip>
            ) : null}
            <a href="/mitre" className="text-xs text-teal-700 hover:underline dark:text-teal-300">
              {t('攻擊手法總覽 →')}
            </a>
          </FilterRow>
        ) : null}
        <SearchBox
          t={t}
          action={base}
          q={f.q}
          placeholder={t('標題、指標、規則或主機')}
          keep={{
            tab: agentId ? 'findings' : undefined,
            agent_id: agentId ? undefined : f.agentId,
            status: f.status.join(','),
            severity: f.severity.join(','),
            scanner: f.scanner.join(','),
            technique: f.technique,
            control: f.control,
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
