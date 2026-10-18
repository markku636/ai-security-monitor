// 可疑／危險 IP 排名（連線頁上方；server component）。勾選與批次操作在 IpBatchSelect（client）。
import Link from 'next/link';
import type { ReactNode } from 'react';
import { DirectionBadge, VerdictChip } from '@/components/security/Verdict';
import { IpBatchBar, IpSelectAll, IpSelectCheckbox, IpSelectionProvider } from '@/components/security/IpBatchSelect';
import { InlineIpNote } from '@/components/security/InlineIpNote';
import { IpLink } from '@/components/security/IpLink';
import { IpRiskBadge, IpRiskLegend } from '@/components/security/IpRisk';
import { Card } from '@/components/ui/Card';
import { CountryFlag } from '@/components/ui/CountryFlag';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { RankSort, RankSortKey, RiskyIpRanking as Ranking, RankWindow } from '@/lib/queries/connections';
import { RANK_WINDOWS } from '@/lib/queries/connections';

const TH = 'whitespace-nowrap px-2 py-1.5 text-left text-xs font-medium text-slate-500';
const TD = 'px-2 py-2 align-top';

/** 可點的表頭：目前排序的欄位標 ▲／▼，再點一次反向。 */
function SortTh({
  k,
  sort,
  hrefFor,
  right,
  title,
  children,
}: {
  k: RankSortKey;
  sort: RankSort;
  hrefFor: (k: RankSortKey) => string;
  right?: boolean;
  title?: string;
  children: ReactNode;
}) {
  const active = sort.key === k;
  return (
    <th className={`${TH} ${right ? 'text-right' : ''}`} title={title} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <Link
        href={hrefFor(k)}
        scroll={false}
        className={`inline-flex items-center gap-1 hover:text-teal-700 dark:hover:text-teal-300 ${active ? 'text-slate-800 dark:text-slate-100' : ''}`}
      >
        {children}
        <span className={active ? '' : 'opacity-30'}>{active ? (sort.dir === 'asc' ? '▲' : '▼') : '↕'}</span>
      </Link>
    </th>
  );
}

export function RiskyIpRanking({
  t,
  ranking,
  moreHref,
  lessHref,
  rankWindow,
  windowHref,
  sort,
  sortHref,
  unanalyzed,
  persistKey,
  fullListHref,
  toolbar,
  footer,
  emptyText,
}: {
  t: TFn;
  ranking: Ranking;
  /** 排名裡還沒查過外部情資的公網 IP（給了就顯示「查詢全部未分析」）。 */
  unanalyzed?: { ips: string[]; total: number };
  /** 完整清單頁：勾選跨頁保留在 sessionStorage 的 key。 */
  persistKey?: string;
  /** 「看完整清單 →」的連結。 */
  fullListHref?: string;
  /** 標題列下方的額外篩選（完整清單頁用）。 */
  toolbar?: ReactNode;
  /** 表格下方（分頁）。 */
  footer?: ReactNode;
  /** 沒有任何列時的說明。 */
  emptyText?: string;
  /** 目前的排序與換排序的連結（保留其他篩選）。 */
  sort: RankSort;
  sortHref: (k: RankSortKey) => string;
  /** 顯示更多名次的連結（已全部列出時不給）。 */
  moreHref?: string;
  /** 收合回前幾名的連結（目前是展開狀態時才給）。 */
  lessHref?: string;
  /** 時間範圍（依最後一次被判可疑）與切換連結；沒給就不顯示切換。 */
  rankWindow?: RankWindow;
  windowHref?: (w: RankWindow) => string;
}) {
  const { items, total } = ranking;
  const windowLabel: Record<RankWindow, string> = { '7': t('最近 7 天'), '30': t('最近 30 天'), all: t('全部時間') };
  return (
    <Card
      title={
        <span className="flex flex-wrap items-baseline gap-x-2">
          {t('可疑 IP 排名')}
          <span className="text-xs font-normal text-slate-500">
            {t('曾被判定可疑或危險的遠端 IP，共 {n} 個；點表頭可以換排序', { n: total })}
          </span>
          {rankWindow && windowHref ? (
            <span
              className="ml-auto flex gap-1 text-xs font-normal"
              title={t('依「最後一次被判可疑」的時間篩選：之後判定變好的 IP（例如舊的誤報）過了這段時間就不再列出')}
            >
              {RANK_WINDOWS.map((w) => (
                <Link
                  key={w}
                  href={windowHref(w)}
                  scroll={false}
                  aria-current={w === rankWindow ? 'true' : undefined}
                  className={`rounded-full border px-2 py-0.5 ${
                    w === rankWindow
                      ? 'border-teal-600 bg-teal-600 text-white'
                      : 'border-slate-300 text-slate-600 hover:border-teal-500 dark:border-slate-700 dark:text-slate-300'
                  }`}
                >
                  {windowLabel[w]}
                </Link>
              ))}
            </span>
          ) : null}
        </span>
      }
    >
      {toolbar ? <div className="mb-3">{toolbar}</div> : null}
      {items.length ? (
        <IpSelectionProvider rows={items.map((r) => ({ ip: r.remoteIp, isPublic: r.risk.kind !== 'private' }))} persistKey={persistKey}>
        <IpBatchBar unanalyzed={unanalyzed?.ips} unanalyzedTotal={unanalyzed?.total} />
        <div className="mb-2">
          <IpRiskLegend t={t} />
        </div>
        <div className="-mx-2 overflow-x-auto">
          <table className="w-full min-w-[960px] text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-800">
                <th className={`${TH} w-8`}>
                  <IpSelectAll />
                </th>
                <th className={TH}>#</th>
                <SortTh k="verdict" sort={sort} hrefFor={sortHref}>
                  {t('判定')}
                </SortTh>
                <SortTh
                  k="risk"
                  sort={sort}
                  hrefFor={sortHref}
                  title={t('外部威脅情資（AbuseIPDB、GreyNoise 等第三方資料庫）算出的風險分數 0–100，越高越可能是惡意來源；「—」是還沒查過，勾選後按「查詢外部情資」就會有')}
                >
                  {t('外部風險')} ⓘ
                </SortTh>
                <SortTh k="ip" sort={sort} hrefFor={sortHref}>
                  {t('遠端 IP')}
                </SortTh>
                <SortTh k="seen" sort={sort} hrefFor={sortHref} right title={t('每次連線快照看到一次就加 1（同一個 IP 的不同 port、不同主機會加總）')}>
                  {t('累計次數')} ⓘ
                </SortTh>
                <SortTh k="live" sort={sort} hrefFor={sortHref} right title={t('最新快照裡仍判定可疑或危險的連線條數；0 代表目前沒有在連')}>
                  {t('目前')} ⓘ
                </SortTh>
                <SortTh k="hosts" sort={sort} hrefFor={sortHref} right>
                  {t('主機')}
                </SortTh>
                <SortTh k="port" sort={sort} hrefFor={sortHref}>
                  {t('方向／port')}
                </SortTh>
                <SortTh k="process" sort={sort} hrefFor={sortHref}>
                  {t('行程')}
                </SortTh>
                <SortTh k="geo" sort={sort} hrefFor={sortHref}>
                  {t('國家／組織')}
                </SortTh>
                <SortTh k="note" sort={sort} hrefFor={sortHref}>
                  {t('備註')}
                </SortTh>
                <SortTh k="last" sort={sort} hrefFor={sortHref}>
                  {t('最後看到')}
                </SortTh>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {items.map((r) => (
                <tr key={r.remoteIp}>
                  <td className={TD}>
                    <IpSelectCheckbox ip={r.remoteIp} />
                  </td>
                  <td className={`${TD} tabular-nums text-slate-500`}>{r.rank}</td>
                  <td className={TD}>
                    <VerdictChip verdict={r.worst} t={t} />
                  </td>
                  <td className={TD}>
                    <IpRiskBadge t={t} risk={r.risk} />
                  </td>
                  <td className={TD}>
                    <IpLink ip={r.remoteIp} className="font-mono text-xs" risk={r.risk} t={t}>
                      {r.remoteIp}
                    </IpLink>
                    {r.domain ? (
                      <div className="max-w-[14rem] truncate text-xs text-slate-500" title={t('主機連線時解析出的網域：{d}', { d: r.domain })}>
                        {r.domain}
                      </div>
                    ) : null}
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
                    {r.country || r.org ? (
                      <span className="inline-flex flex-wrap items-center gap-1">
                        {r.country ? <CountryFlag code={r.country} t={t} /> : null}
                        {r.org ? <span>{r.org}</span> : null}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className={`${TD} max-w-[16rem] text-xs`}>
                    <InlineIpNote ip={r.remoteIp} note={r.note} />
                  </td>
                  <td className={`${TD} whitespace-nowrap text-xs text-slate-500`} title={t('第一次看到：{at}', { at: since(r.firstSeenAt, t) })}>
                    {since(r.lastSeenAt, t)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </IpSelectionProvider>
      ) : (
        <p className="text-sm text-slate-500">{emptyText ?? t('目前沒有被判定可疑或危險的遠端 IP。')}</p>
      )}
      {footer ? <div className="mt-3">{footer}</div> : null}
      {moreHref || lessHref || fullListHref ? (
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
          {fullListHref ? (
            <Link href={fullListHref} className="ml-auto text-teal-700 hover:underline dark:text-teal-400">
              {t('看完整清單（{n} 個）→', { n: total })}
            </Link>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
