import { ActionsTable, type ActionView } from '@/components/security/ActionsTable';
import { actionStatusText } from '@/components/security/actionLabels';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow, toggled } from '@/components/ui/Filters';
import { ACTION_STATUSES, listActions, type ActionStatus } from '@/lib/actions/store';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { getT } from '@/lib/i18n/server';
import { listParam, toQuery } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export default async function ActionsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const status = listParam(sp, 'status', ACTION_STATUSES);
  const r = await listActions(getDb(), { status, limit: 200 });
  const rows: ActionView[] = r.items.map((a) => ({
    id: a.id,
    agentId: a.agentId,
    hostname: a.hostname,
    agentAccepts: a.agentAccepts,
    kind: a.kind,
    params: a.params,
    reason: a.reason,
    status: a.status,
    destructive: a.destructive,
    proposedBy: a.proposedBy,
    createdAt: a.createdAt.toISOString(),
    reviewedBy: a.reviewedBy,
    reviewedAt: a.reviewedAt ? a.reviewedAt.toISOString() : null,
    completedAt: a.completedAt ? a.completedAt.toISOString() : null,
    resultOk: a.resultOk,
    resultOutput: a.resultOutput,
  }));
  const chip = (s: ActionStatus) => `/actions${toQuery({ status: toggled(status, s) })}`;
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('封鎖審核')}</h1>
        <p className="text-sm text-slate-500">
          {t('封鎖 IP、關閉 port 等防禦動作：核准後由主機上的 asa 驗證簽章再執行，結果會回報到這裡。')}
        </p>
      </header>
      <div className="rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        <FilterRow label={t('狀態')}>
          {ACTION_STATUSES.map((s) => (
            <FilterChip key={s} href={chip(s)} active={status.includes(s)}>
              {actionStatusText(t, s)} <span className="opacity-70">{r.counts[s] ?? 0}</span>
            </FilterChip>
          ))}
        </FilterRow>
      </div>
      {rows.length ? (
        <ActionsTable rows={rows} />
      ) : (
        <EmptyState title={t('沒有動作')}>{t('在「發現」裡展開一筆有建議動作的項目，按「送審」就會出現在這裡。')}</EmptyState>
      )}
    </div>
  );
}
