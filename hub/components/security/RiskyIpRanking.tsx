// 可疑／危險 IP 排名（連線頁上方；server component）。
import Link from 'next/link';
import { DirectionBadge, VerdictChip } from '@/components/security/Verdict';
import { IpLink } from '@/components/security/IpLink';
import { Card } from '@/components/ui/Card';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { RiskyIpRanking as Ranking } from '@/lib/queries/connections';

const TH = 'whitespace-nowrap px-2 py-1.5 text-left text-xs font-medium text-slate-500';
const TD = 'px-2 py-2 align-top';

export function RiskyIpRanking({
  t,
  ranking,
  moreHref,
  lessHref,
}: {
  t: TFn;
  ranking: Ranking;
  /** 顯示更多名次的連結（已全部列出時不給）。 */
  moreHref?: string;
  /** 收合回前幾名的連結（目前是展開狀態時才給）。 */
  lessHref?: string;
}) {
  const { items, total } = ranking;
  return (
    <Card
      title={
        <span className="flex flex-wrap items-baseline gap-x-2">
          {t('可疑 IP 排名')}
          <span className="text-xs font-normal text-slate-500">
            {t('曾被判定可疑或危險的遠端 IP，共 {n} 個；依危險程度與累計次數排序', { n: total })}
          </span>
        </span>
      }
    >
      {items.length ? (
        <div className="-mx-2 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-800">
                <th className={TH}>#</th>
                <th className={TH}>{t('判定')}</th>
                <th className={TH}>{t('遠端 IP')}</th>
                <th className={`${TH} text-right`} title={t('每次連線快照看到一次就加 1（同一個 IP 的不同 port、不同主機會加總）')}>
                  {t('累計次數')} ⓘ
                </th>
                <th className={`${TH} text-right`} title={t('最新快照裡仍判定可疑或危險的連線條數；0 代表目前沒有在連')}>
                  {t('目前')} ⓘ
                </th>
                <th className={`${TH} text-right`}>{t('主機')}</th>
                <th className={TH}>{t('方向／port')}</th>
                <th className={TH}>{t('行程')}</th>
                <th className={TH}>{t('國家／組織')}</th>
                <th className={TH}>{t('最後看到')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {items.map((r) => (
                <tr key={r.remoteIp}>
                  <td className={`${TD} tabular-nums text-slate-500`}>{r.rank}</td>
                  <td className={TD}>
                    <VerdictChip verdict={r.worst} t={t} />
                  </td>
                  <td className={TD}>
                    <IpLink ip={r.remoteIp} className="font-mono text-xs">
                      {r.remoteIp}
                    </IpLink>
                  </td>
                  <td className={`${TD} text-right font-semibold tabular-nums`}>{r.seen}</td>
                  <td className={`${TD} text-right tabular-nums ${r.live ? 'text-amber-600 dark:text-amber-400' : 'text-slate-400'}`}>
                    {r.live}
                  </td>
                  <td className={`${TD} text-right tabular-nums`}>{r.hosts}</td>
                  <td className={TD}>
                    <div className="flex flex-wrap items-center gap-1">
                      {r.directions.map((d) => (
                        <DirectionBadge key={d} direction={d} t={t} />
                      ))}
                      <span className="font-mono text-xs text-slate-500">{r.ports.join(', ')}</span>
                    </div>
                  </td>
                  <td className={`${TD} text-xs`}>{r.processes.length ? r.processes.join('、') : '—'}</td>
                  <td className={`${TD} text-xs text-slate-500`}>
                    {[r.country, r.org].filter(Boolean).join(' · ') || '—'}
                  </td>
                  <td className={`${TD} whitespace-nowrap text-xs text-slate-500`} title={t('第一次看到：{at}', { at: since(r.firstSeenAt, t) })}>
                    {since(r.lastSeenAt, t)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-slate-500">{t('目前沒有被判定可疑或危險的遠端 IP。')}</p>
      )}
      {moreHref || lessHref ? (
        <div className="mt-2 flex gap-4 text-sm">
          {moreHref ? (
            <Link href={moreHref} className="text-teal-700 hover:underline dark:text-teal-400">
              {t('顯示前 50 名 →')}
            </Link>
          ) : null}
          {lessHref ? (
            <Link href={lessHref} className="text-teal-700 hover:underline dark:text-teal-400">
              {t('只看前 10 名')}
            </Link>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
