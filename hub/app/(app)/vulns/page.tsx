import Link from 'next/link';
import { FleetAppsTable, SupportBadge } from '@/components/security/PostureViews';
import { Card, Stat } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { requireAdmin } from '@/lib/auth/require';
import { HostFilter } from '@/components/ui/HostFilter';
import { strParam } from '@/lib/queries/params';
import { since } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import { vulnOverview } from '@/lib/queries/posture';

export const dynamic = 'force-dynamic';

const TABLE = 'overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900';
const HEAD = 'border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap';
const ROW = 'border-b border-slate-100 last:border-0 dark:border-slate-800';

export default async function VulnsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const agentId = strParam(await searchParams, 'agent_id', 64);
  const v = await vulnOverview(agentId);
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('漏洞與更新')}</h1>
        <p className="text-sm text-slate-500">{t('各主機的作業系統支援期限、更新狀態、已知漏洞版本的軟體，以及 Linux 套件的 OSV 查詢結果。')}</p>
      </header>
      <HostFilter t={t} action="/vulns" current={agentId} />
      {!v.hosts ? (
        <EmptyState title={t('還沒有漏洞資料')}>{t('代理程式執行 asa scan 或 asa watch 時會一併回報（需要 asa 0.1 以上）。')}</EmptyState>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label={t('作業系統已停止支援')} value={v.unsupported} hint={t('即將停止支援：{n}', { n: v.endingSoon })} />
            <Stat label={t('有 KEV 漏洞的主機')} value={v.kevHosts} hint={t('CISA 確認已被用於攻擊')} />
            <Stat label={t('已知漏洞軟體')} value={v.apps.length} hint={t('{n} 台主機回報', { n: v.hosts })} />
            <Stat label={t('更新落後')} value={v.stalePatches} hint={t('超過 45 天沒更新或有待裝安全性更新')} />
          </div>
          {v.apps.length ? (
            <section className="space-y-2">
              <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{t('有已知漏洞或已停止支援的軟體')}</h2>
              <FleetAppsTable t={t} rows={v.apps} />
            </section>
          ) : null}
          <div className="grid gap-4 xl:grid-cols-2">
            <Card title={t('作業系統支援期限')}>
              <div className={TABLE}>
                <table className="w-full text-left text-sm">
                  <thead className={HEAD}>
                    <tr>
                      <th className="px-3 py-2">{t('主機')}</th>
                      <th className="px-3 py-2">{t('系統')}</th>
                      <th className="px-3 py-2">{t('狀態')}</th>
                      <th className="px-3 py-2">{t('停止支援日')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {v.os.map((o) => (
                      <tr key={o.agentId} className={ROW}>
                        <td className="px-3 py-2">
                          <Link className="hover:underline" href={`/agents/${encodeURIComponent(o.agentId)}?tab=vulns`}>
                            {o.hostname}
                          </Link>
                        </td>
                        <td className="px-3 py-2 text-xs">{o.support?.product || o.name}</td>
                        <td className="px-3 py-2">
                          <SupportBadge t={t} status={o.support?.status} />
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-xs tabular-nums">{o.support?.eol ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <Card title={t('更新狀態')}>
              {v.patches.length ? (
                <div className={TABLE}>
                  <table className="w-full text-left text-sm">
                    <thead className={HEAD}>
                      <tr>
                        <th className="px-3 py-2">{t('主機')}</th>
                        <th className="px-3 py-2">{t('最近一次更新')}</th>
                        <th className="px-3 py-2">{t('待安裝（安全性）')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {v.patches.map((p) => (
                        <tr key={p.agentId} className={ROW}>
                          <td className="px-3 py-2">
                            <Link className="hover:underline" href={`/agents/${encodeURIComponent(p.agentId)}?tab=vulns`}>
                              {p.hostname}
                            </Link>
                          </td>
                          <td className={`px-3 py-2 text-xs ${(p.lastPatch?.days ?? 0) > 45 ? 'font-semibold text-amber-700 dark:text-amber-400' : ''}`}>
                            {p.lastPatch ? t('{id}（{days} 天前）', { id: p.lastPatch.id, days: p.lastPatch.days }) : '—'}
                          </td>
                          <td className="px-3 py-2 text-xs tabular-nums">{p.pending ? `${p.pending.total}（${p.pending.security}）` : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-slate-500">{t('沒有更新紀錄。')}</p>
              )}
            </Card>
          </div>
          {v.osv.length ? (
            <Card title={t('Linux 套件（OSV）')}>
              <div className={TABLE}>
                <table className="w-full text-left text-sm">
                  <thead className={HEAD}>
                    <tr>
                      <th className="px-3 py-2">{t('主機')}</th>
                      <th className="px-3 py-2">{t('生態系')}</th>
                      <th className="px-3 py-2">{t('有漏洞的套件')}</th>
                      <th className="px-3 py-2">{t('嚴重／高')}</th>
                      <th className="px-3 py-2">KEV</th>
                    </tr>
                  </thead>
                  <tbody>
                    {v.osv.map((o) => (
                      <tr key={o.agentId} className={ROW}>
                        <td className="px-3 py-2">
                          <Link className="hover:underline" href={`/agents/${encodeURIComponent(o.agentId)}?tab=vulns`}>
                            {o.hostname}
                          </Link>
                        </td>
                        <td className="px-3 py-2 text-xs">{o.ecosystem}</td>
                        <td className="px-3 py-2 tabular-nums">
                          {o.packages} / {o.queried}
                        </td>
                        <td className="px-3 py-2 tabular-nums">
                          {o.critical} / {o.high}
                        </td>
                        <td className={`px-3 py-2 tabular-nums ${o.kev ? 'font-semibold text-red-700 dark:text-red-400' : ''}`}>{o.kev}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          ) : null}
          <p className="text-xs text-slate-500">
            {t('資料來源：OSV.dev、CISA KEV、NVD；作業系統支援期限整理自微軟、各發行版與 Apple 官方生命週期頁面。')}{' '}
            {v.os[0] ? t('最新回報 {when}', { when: since(v.os.reduce((a, o) => (o.at > a ? o.at : a), v.os[0].at), t) }) : null}
          </p>
        </>
      )}
    </div>
  );
}
