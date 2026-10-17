// 依裝置篩選：主機不多時用晶片（純連結），多時改成 GET 表單下拉；其他篩選參數一律保留。
import type { TFn } from '@/lib/i18n/core';
import { listAgents } from '@/lib/queries/agents';
import { toQuery } from '@/lib/queries/params';
import { FilterChip, FilterRow } from './Filters';

const MAX_CHIPS = 12;

export async function HostFilter({
  t,
  action,
  current,
  keep = {},
}: {
  t: TFn;
  action: string;
  current?: string;
  keep?: Record<string, string | number | undefined>;
}) {
  const hosts = (await listAgents()).map((a) => ({ id: a.id, hostname: a.hostname }));
  if (hosts.length < 2 && !current) return null;
  const href = (agentId?: string) => action + toQuery({ ...keep, agent_id: agentId });
  if (hosts.length <= MAX_CHIPS) {
    return (
      <FilterRow label={t('裝置')}>
        <FilterChip href={href()} active={!current}>
          {t('所有裝置')}
        </FilterChip>
        {hosts.map((h) => (
          <FilterChip key={h.id} href={href(h.id)} active={h.id === current}>
            {h.hostname}
          </FilterChip>
        ))}
      </FilterRow>
    );
  }
  return (
    <FilterRow label={t('裝置')}>
      <form action={action} method="get" className="flex gap-2">
        {Object.entries(keep).map(([k, v]) => (v !== undefined && v !== '' ? <input key={k} type="hidden" name={k} value={String(v)} /> : null))}
        <select
          name="agent_id"
          defaultValue={current ?? ''}
          className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900"
        >
          <option value="">{t('所有裝置')}</option>
          {hosts.map((h) => (
            <option key={h.id} value={h.id}>
              {h.hostname}
            </option>
          ))}
        </select>
        <button type="submit" className="rounded-md border border-slate-300 px-3 py-1 text-sm hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">
          {t('套用')}
        </button>
      </form>
    </FilterRow>
  );
}
