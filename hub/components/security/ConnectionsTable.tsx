// 連線表：方向徽章＋判定晶片＋理由（情資來源可點）＋國家／ASN＋行程。
import Link from 'next/link';
import { endpoint } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { IpRisk } from '@/lib/ipintel/types';
import type { ConnectionRow, ConnSortKey } from '@/lib/queries/connections';
import { SortHeader } from '@/components/ui/SortHeader';
import { CountryFlag } from '@/components/ui/CountryFlag';
import { IpLink } from './IpLink';
import { DirectionBadge, ReasonList, VerdictChip } from './Verdict';

export function ConnectionsTable({
  rows,
  t,
  showHost = true,
  notes = {},
  risks = {},
  sort,
  sortHref,
}: {
  rows: ConnectionRow[];
  /** 目前排序與換排序的連結；有給才把表頭變成可點。 */
  sort?: { key: ConnSortKey; dir: 'asc' | 'desc' };
  sortHref?: (k: ConnSortKey) => string;
  t: TFn;
  showHost?: boolean;
  /** 遠端 IP → 人工備註（有備註的 IP 旁邊顯示 📝，滑過看全文）。 */
  notes?: Record<string, string>;
  /** 遠端 IP → 快取的外部風險（IP 前面顯示圖示）。 */
  risks?: Record<string, IpRisk>;
}) {
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800">
          <tr>
            {(
              [
                ['verdict', t('判定')],
                ['direction', t('方向')],
                ...(showHost ? [['host', t('主機')] as const] : []),
                ['remote', t('遠端')],
                ['country', t('國家／組織')],
                ['process', t('行程')],
                ['reason', t('理由與來源')],
              ] as [ConnSortKey, string][]
            ).map(([k, label]) =>
              sort && sortHref ? (
                <SortHeader key={k} active={sort.key === k} dir={sort.dir} href={sortHref(k)} title={t('點一下依「{c}」排序，再點一次反向', { c: label })}>
                  {label}
                </SortHeader>
              ) : (
                <th key={k} className="px-3 py-2">
                  {label}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id} className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
              <td className="px-3 py-2">
                <VerdictChip verdict={c.verdict} t={t} />
              </td>
              <td className="px-3 py-2 whitespace-nowrap">
                <DirectionBadge direction={c.direction} t={t} />
                <div className="mt-1 text-xs text-slate-500">
                  {c.proto} · {c.state}
                </div>
              </td>
              {showHost ? (
                <td className="px-3 py-2 whitespace-nowrap">
                  <Link href={`/agents/${encodeURIComponent(c.agentId)}?tab=connections`} className="hover:underline">
                    {c.hostname}
                  </Link>
                </td>
              ) : null}
              <td className="px-3 py-2 font-mono text-xs">
                {c.direction === 'listening' ? (
                  <span>{endpoint(c.localIp, c.localPort)}</span>
                ) : (
                  <>
                    <div>
                      <IpLink ip={c.remoteIp} risk={c.remoteIp ? risks[c.remoteIp] : undefined} t={t}>
                        {endpoint(c.remoteIp, c.remotePort)}
                      </IpLink>
                      {c.remoteIp && notes[c.remoteIp] ? (
                        <span className="ml-1 cursor-help font-sans" title={t('備註：{note}', { note: notes[c.remoteIp] })}>
                          📝
                        </span>
                      ) : null}
                    </div>
                    <div className="text-slate-500">{t('本機 {ep}', { ep: endpoint(c.localIp, c.localPort) })}</div>
                  </>
                )}
              </td>
              <td className="px-3 py-2 text-xs">
                {c.country || c.org ? (
                  <>
                    <div>{c.country ? <CountryFlag code={c.country} t={t} /> : '—'}</div>
                    <div className="text-slate-500">
                      {c.asn ? `AS${c.asn} ` : ''}
                      {c.org ?? ''}
                    </div>
                  </>
                ) : (
                  <span className="text-slate-400">—</span>
                )}
              </td>
              <td className="px-3 py-2 text-xs">
                <div className="font-medium">{c.processName ?? '—'}</div>
                <div className="text-slate-500">
                  {c.pid != null ? `pid ${c.pid}` : ''}
                  {c.exe ? (
                    <span className="block max-w-[18rem] truncate" title={c.exe}>
                      {c.exe}
                    </span>
                  ) : null}
                </div>
              </td>
              <td className="px-3 py-2">
                <ReasonList reasons={c.reasons} t={t} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** DB-IP 授權要求的標註（有顯示國家／ASN 的頁面放在底部）。 */
export function GeoAttribution({ t }: { t: TFn }) {
  return (
    <p className="text-xs text-slate-500">
      {t('IP 地理位置與 ASN 資料：')}
      <a href="https://db-ip.com" target="_blank" rel="noreferrer noopener" className="underline">
        IP Geolocation by DB-IP
      </a>{' '}
      (CC BY 4.0)
    </p>
  );
}
