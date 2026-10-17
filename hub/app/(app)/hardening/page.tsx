import Link from 'next/link';
import { FleetFailedTable } from '@/components/security/PostureViews';
import { Card, Stat } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { ScorePill } from '@/components/ui/Severity';
import { requireAdmin } from '@/lib/auth/require';
import { HostFilter } from '@/components/ui/HostFilter';
import { strParam } from '@/lib/queries/params';
import { since } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import { hardeningOverview } from '@/lib/queries/posture';

export const dynamic = 'force-dynamic';

const TABLE = 'overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900';
const HEAD = 'border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap';
const ROW = 'border-b border-slate-100 last:border-0 dark:border-slate-800';

export default async function HardeningPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const agentId = strParam(await searchParams, 'agent_id', 64);
  const h = await hardeningOverview(agentId);
  const failing = h.hosts.filter((x) => x.fail > 0).length;
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('安全設定')}</h1>
        <p className="text-sm text-slate-500">{t('各主機的安全設定檢查：UAC、防毒、磁碟加密、SSH、核心參數、自動更新等，分數依嚴重度加權。')}</p>
      </header>
      <HostFilter t={t} action="/hardening" current={agentId} />
      {!h.hosts.length ? (
        <EmptyState title={t('還沒有硬化檢查資料')}>{t('代理程式執行 ai-security-monitor scan 或 ai-security-monitor watch 時會一併回報；本機可用 ai-security-monitor harden 先看結果。')}</EmptyState>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <Stat label={t('平均硬化分數')} value={<ScorePill score={h.average} />} hint={t('{n} 台主機回報', { n: h.hosts.length })} />
            <Stat label={t('有未通過項目的主機')} value={failing} />
            <Stat label={t('最常未通過')} value={h.topFailed[0]?.hosts.length ?? 0} hint={h.topFailed[0]?.check.title ?? '—'} />
          </div>
          {h.topFailed.length ? (
            <section className="space-y-2">
              <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('最常未通過的檢查')}</h2>
              <FleetFailedTable t={t} rows={h.topFailed.slice(0, 40)} />
            </section>
          ) : null}
          <Card title={t('各主機分數')}>
            <div className={TABLE}>
              <table className="w-full text-left text-sm">
                <thead className={HEAD}>
                  <tr>
                    <th className="px-3 py-2">{t('主機')}</th>
                    <th className="px-3 py-2">{t('系統')}</th>
                    <th className="px-3 py-2">{t('分數')}</th>
                    <th className="px-3 py-2">{t('通過／未通過／不適用')}</th>
                    <th className="px-3 py-2">{t('回報時間')}</th>
                  </tr>
                </thead>
                <tbody>
                  {h.hosts.map((x) => (
                    <tr key={x.agentId} className={ROW}>
                      <td className="px-3 py-2">
                        <Link className="hover:underline" href={`/agents/${encodeURIComponent(x.agentId)}?tab=hardening`}>
                          {x.hostname}
                        </Link>
                        {x.needsAdmin ? <div className="text-xs text-slate-500">{t('{n} 項需要管理員權限', { n: x.needsAdmin })}</div> : null}
                      </td>
                      <td className="px-3 py-2 text-xs">{x.osFamily}</td>
                      <td className="px-3 py-2">
                        <ScorePill score={x.score} />
                      </td>
                      <td className="px-3 py-2 tabular-nums">
                        {x.pass} / <span className={x.fail ? 'font-semibold text-red-700 dark:text-red-400' : ''}>{x.fail}</span> / {x.na}
                      </td>
                      <td className="px-3 py-2 text-xs text-slate-500">{since(x.at, t)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
