// IP／網域在所有主機裡的情資命中、目前連線與歷史（情資頁查詢與 IP 分析頁共用）。
import Link from 'next/link';
import { Card } from '@/components/ui/Card';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { lookupIndicator } from '@/lib/queries/intel';
import type { Reason } from '@/lib/queries/connections';
import { DirectionBadge, ReasonList, VerdictChip } from './Verdict';
import { CountryFlag } from '@/components/ui/CountryFlag';
import { httpsHref } from '@/lib/links';

export async function IndicatorDetails({ t, q, title }: { t: TFn; q: string; title?: string }) {
  const r = await lookupIndicator(q);
  const empty = !r.hits.length && !r.connections.length && !r.destinations.length;
  return (
    <Card title={title ?? t('查詢結果：{q}', { q })}>
      {empty ? <p className="text-sm text-slate-500">{t('沒有任何主機連過這個位址，也沒有情資命中紀錄。')}</p> : null}
      {r.hits.length ? (
        <div className="mb-4">
          <h3 className="mb-1 text-xs font-semibold text-slate-500">{t('列名的情資來源')}</h3>
          <ul className="space-y-1 text-sm">
            {r.hits.map((h, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <a href={httpsHref(h.sourceUrl)} target="_blank" rel="noreferrer noopener" className="font-medium hover:underline">
                  {h.vendor} · {h.feedName}
                </a>
                <span className="text-xs text-slate-500">
                  {t('信心 {n}%', { n: h.confidence })} · {h.license} · {h.hostname} · {since(h.seenAt, t)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {r.connections.length ? (
        <div className="mb-4">
          <h3 className="mb-1 text-xs font-semibold text-slate-500">{t('目前的連線')}</h3>
          <ul className="space-y-1 text-sm">
            {r.connections.map((c, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <VerdictChip verdict={c.verdict} t={t} />
                <DirectionBadge direction={c.direction} t={t} />
                <Link href={`/agents/${encodeURIComponent(c.agentId)}?tab=connections&q=${encodeURIComponent(q)}`} className="hover:underline">
                  {c.hostname}
                </Link>
                <span className="text-xs text-slate-500">
                  {c.processName ?? '—'} · {c.direction === 'inbound' ? `:${c.localPort}` : `:${c.remotePort ?? ''}`} · {c.state}
                  {c.country ? ' · ' : ''}
                  {c.country ? <CountryFlag code={c.country} t={t} /> : null}
                  {c.asn ? ` · AS${c.asn}` : ''}
                  {c.org ? ` ${c.org}` : ''}
                </span>
                <ReasonList reasons={(c.reasons ?? []) as Reason[]} t={t} />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {r.destinations.length ? (
        <div>
          <h3 className="mb-1 text-xs font-semibold text-slate-500">{t('歷史紀錄')}</h3>
          <ul className="space-y-1 text-sm">
            {r.destinations.map((d, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <VerdictChip verdict={d.worstVerdict} t={t} />
                <DirectionBadge direction={d.direction} t={t} />
                <span>{d.hostname}</span>
                <span className="text-xs text-slate-500">
                  {d.processName ?? '—'} · :{d.remotePort} · {t('看到 {n} 次，最後 {at}', { n: d.seenCount, at: since(d.lastSeenAt, t) })}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}
