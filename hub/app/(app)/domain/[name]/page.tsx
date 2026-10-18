import { BackButton } from '@/components/ui/BackButton';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { BlocklistButtons } from '@/components/dns/BlocklistButtons';
import { IndicatorDetails } from '@/components/security/IndicatorDetails';
import { sevText, statusText } from '@/components/security/Verdict';
import { Badge } from '@/components/ui/Badge';
import { Card, Stat } from '@/components/ui/Card';
import { Hint } from '@/components/ui/Hint';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { getProtect, listedBy } from '@/lib/dns/protect';
import { since } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import { domainDetail, normalizeDomain } from '@/lib/queries/dns';

export const dynamic = 'force-dynamic';

const BTN = 'rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950';

/** 外部查詢只放連結（使用者自己點），hub 不會把網域送出去。 */
function externalLookups(d: string): [string, string][] {
  const e = encodeURIComponent(d);
  return [
    ['VirusTotal', `https://www.virustotal.com/gui/domain/${e}`],
    ['urlscan.io', `https://urlscan.io/domain/${e}`],
    ['Cisco Talos', `https://talosintelligence.com/reputation_center/lookup?search=${e}`],
    ['crt.sh', `https://crt.sh/?q=${e}`],
  ];
}

export default async function DomainPage({ params }: { params: Promise<{ name: string }> }) {
  await requireAdmin();
  const { t } = await getT();
  const name = normalizeDomain((await params).name);
  if (!name) notFound();
  const [d, protect] = await Promise.all([domainDetail(name), getProtect(getDb())]);
  const total = d.byHost.reduce((s, r) => s + r.queries, 0);
  const hosts = new Set(d.byHost.map((r) => r.agentId)).size;
  const maxHour = Math.max(1, ...d.hourly.map((h) => h.queries));
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <div className="mb-1">
            <BackButton fallback="/dns" />
          </div>
          <p className="text-xs text-slate-500">
            <Link href="/dns" className="hover:underline">
              {t('DNS')}
            </Link>{' '}
            / {t('網域分析')}
          </p>
          <h1 className="break-all font-mono text-xl font-semibold">{name}</h1>
          <p className="text-sm text-slate-500">{t('這個網域在所有主機的 DNS 紀錄：誰查過、解析到哪些 IP、情資有沒有列名。')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link href={`/ai?scope=indicator&q=${encodeURIComponent(name)}`} className={BTN}>
            {t('請 AI 分析這個網域')}
          </Link>
          <Link href={`/dns?q=${encodeURIComponent(name)}&days=7`} className={BTN}>
            {t('在 DNS 頁篩選')}
          </Link>
        </div>
      </header>
      <BlocklistButtons domain={name} blockedBy={listedBy(protect.block, name)} allowedBy={listedBy(protect.allow, name)} />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label={t('查詢次數（7 天內）')} value={total.toLocaleString()} />
        <Stat label={t('查過的主機')} value={hosts} />
        <Stat label={t('全部主機第一次看到')} value={d.domain ? since(d.domain.firstSeenAt, t) : '—'} />
        <Stat label={t('最後一次')} value={d.domain ? since(d.domain.lastSeenAt, t) : '—'} />
      </div>
      {d.related.length ? (
        <Card title={t('相關的 DNS 告警')}>
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {d.related.map((f) => (
              <li key={`${f.agentId}/${f.findingId}`} className="flex flex-wrap items-baseline justify-between gap-2 py-1.5">
                <Link className="hover:underline" href={`/findings?scanner=dns&agent_id=${encodeURIComponent(f.agentId)}&q=${encodeURIComponent(name)}`}>
                  {f.title}
                </Link>
                <span className="text-xs text-slate-500">
                  {f.hostname} · {sevText(t, f.severity)} · {statusText(t, f.status)} · {since(f.lastSeenAt, t)}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={t('哪些主機、哪個程式查過')}>
          {d.byHost.length ? (
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-500">
                <tr>
                  <th className="py-1.5 pr-3">{t('主機')}</th>
                  <th className="py-1.5 pr-3">{t('程式')}</th>
                  <th className="py-1.5 pr-3 text-right">{t('次數')}</th>
                  <th className="py-1.5 pr-3">{t('最後一次')}</th>
                </tr>
              </thead>
              <tbody>
                {d.byHost.map((r, i) => (
                  <tr key={i} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="py-1.5 pr-3">
                      <Link className="hover:underline" href={`/dns?agent_id=${encodeURIComponent(r.agentId)}&q=${encodeURIComponent(name)}&days=7`}>
                        {r.hostname}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-3 text-xs">{r.process || <span className="text-slate-400">—</span>}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{r.queries.toLocaleString()}</td>
                    <td className="py-1.5 pr-3 text-xs text-slate-500">{since(r.last, t)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-slate-500">{t('7 天內沒有主機查過這個網域')}</p>
          )}
        </Card>
        <Card
          title={
            <>
              {t('解析到的 IP')} <Hint text={t('DNS 回答的位址；點進去看那個 IP 的情資與連線紀錄。CDN 的網域常會有很多個。')} />
            </>
          }
        >
          {d.ips.length ? (
            <div className="flex flex-wrap gap-2">
              {d.ips.map((ip) => (
                <Link key={ip} className="rounded border border-slate-200 px-1.5 py-0.5 font-mono text-xs hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800" href={`/ip/${encodeURIComponent(ip)}`}>
                  {ip}
                </Link>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500">{t('沒有位址答案')}</p>
          )}
          {d.rcodes.length ? (
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              {d.rcodes.map((r) => (
                <Badge key={r.rcode} tone={r.rcode === 'NOERROR' ? 'ok' : r.rcode === 'NXDOMAIN' ? 'warn' : 'neutral'}>
                  {r.rcode} × {r.queries.toLocaleString()}
                </Badge>
              ))}
            </div>
          ) : null}
        </Card>
      </div>
      {d.names.length > 1 ? (
        <Card title={t('查過的完整名稱')}>
          <ul className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
            {d.names.map((n) => (
              <li key={n.name} className="flex justify-between gap-2">
                <span className="break-all font-mono">{n.name}</span>
                <span className="tabular-nums text-slate-500">{n.queries.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
      {d.hourly.length ? (
        <Card title={t('最近 7 天每小時的查詢次數')}>
          <div className="flex h-24 items-end gap-px" role="img" aria-label={t('最近 7 天每小時的查詢次數')}>
            {d.hourly.map((h) => (
              <div
                key={h.hour.toISOString()}
                className="flex-1 rounded-t bg-teal-600/70 dark:bg-teal-400/60"
                style={{ height: `${Math.max(2, (h.queries / maxHour) * 100)}%` }}
                title={`${h.hour.toLocaleString()} · ${h.queries}`}
              />
            ))}
          </div>
        </Card>
      ) : null}
      <IndicatorDetails t={t} q={name} title={t('情資與連線紀錄')} />
      <Card title={t('外部查詢')}>
        <p className="mb-2 text-xs text-slate-500">{t('在新分頁開啟第三方網站查這個網域；hub 不會自動把網域送給它們。')}</p>
        <div className="flex flex-wrap gap-2">
          {externalLookups(name).map(([n, href]) => (
            <a key={n} href={href} target="_blank" rel="noreferrer noopener" className={BTN}>
              {n}
            </a>
          ))}
        </div>
      </Card>
    </div>
  );
}
