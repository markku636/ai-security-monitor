'use client';

// IP 分析頁「這個 IP 上的網域」：主機自己解析過的（DNS 快取，不經第三方）、反解（PTR）、外部被動 DNS 反查。
// 只有按「查詢網域」才會把 IP 送給第三方；其餘時間只顯示快取。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import { since, utc } from '@/lib/format';
import { useT } from '@/lib/i18n/client';
import type { IpDomainsView, ProviderView } from '@/lib/ipintel/types';
import { skipText } from './IpThreatIntel';

const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SUB = 'text-xs font-semibold text-slate-500';
const CHIP = 'inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-0.5 font-mono text-xs dark:border-slate-700';
const SHOW = 50;

export function IpDomains({ view }: { view: IpDomainsView }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [refresh, setRefresh] = useState(false);
  const [all, setAll] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const willQuery = view.providers.filter((p) => p.willQuery);
  const queried = view.providers.some((p) => p.result);
  const names = all ? view.merged : view.merged.slice(0, SHOW);

  const run = () => {
    setErr(null);
    start(async () => {
      const r = await apiPost<{ error?: string }>('/api/v1/ip-intel/domains', { ip: view.ip, refresh });
      if (!r.ok) {
        setErr(r.data.error === 'lookups_disabled' ? t('外部查詢已被關閉（ASA_HUB_IP_LOOKUPS=off）。') : t('查詢失敗（HTTP {n}）', { n: r.status }));
        return;
      }
      setRefresh(false);
      router.refresh();
    });
  };

  const providerState = (p: ProviderView): string => {
    if (p.result?.ok) {
      const n = p.result.domains?.total ?? 0;
      return p.result.detail ? `${t('{n} 個', { n })} · ${p.result.detail}` : t('{n} 個', { n });
    }
    if (p.result) return skipText(t, p.result.reason);
    if (!p.enabled) return skipText(t, 'disabled');
    if (p.key === 'required' && !p.configured) return skipText(t, 'no-api-key');
    if (!p.willQuery && view.ip.includes(':')) return skipText(t, 'unsupported');
    return t('未查詢');
  };

  return (
    <div className="space-y-4">
      <p className="text-xs text-slate-500">
        {t('同一個 IP 上可能架了很多網站。CDN、雲端與共用主機的 IP 上常有成千上萬個網域，數量多不代表惡意；要看的是有沒有可疑的名稱。')}
      </p>

      <section>
        <h3 className={`${SUB} mb-1.5 flex items-center gap-1`}>
          {t('這些主機連線時解析過的名稱')}
          <Hint text={t('電腦連到這個 IP 之前查過的網域（從 Windows 的 DNS 快取讀，不經第三方網站）。最能說明「是哪個網站」。目前只有 Windows 會回報。')} />
        </h3>
        {view.local.length ? (
          <ul className="flex flex-wrap gap-1.5">
            {view.local.map((d) => (
              <li key={d.domain} className={CHIP} title={`${d.hosts.join('、')} · ${utc(d.lastSeenAt)}`}>
                {d.domain}
                <span className="font-sans text-slate-500">
                  {d.hosts.length > 1 ? t('{n} 台', { n: d.hosts.length }) : d.hosts[0]} · {since(d.lastSeenAt, t)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-slate-500">{t('還沒有主機回報這個 IP 的網域。')}</p>
        )}
      </section>

      <section>
        <h3 className={`${SUB} mb-1.5 flex items-center gap-1`}>
          {t('反解（PTR）')}
          <Hint text={t('IP 的擁有者自己設定的名稱（例如 server-1.example-hosting.net），常看得出是哪家主機商。在「外部威脅情資」按查詢時會一起查。')} />
        </h3>
        <p className="font-mono text-sm">{view.ptr ?? <span className="font-sans text-slate-500">{t('沒有或還沒查')}</span>}</p>
      </section>

      {view.isPublic ? (
        <section className="space-y-2">
          <h3 className={`${SUB} flex items-center gap-1`}>
            {t('外部被動 DNS 反查')}
            <Hint text={t('第三方長期收集的 DNS 紀錄：曾經解析到這個 IP 的網域。資料可能過時（網域早就搬走了），看「最後看到」的時間。')} />
          </h3>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className={BTN} onClick={run} disabled={pending || !view.lookupsEnabled || !willQuery.length}>
              {pending ? t('查詢中…') : queried ? t('重新查詢網域') : t('查詢網域')}
            </button>
            {queried ? (
              <label className="flex items-center gap-1 text-xs text-slate-500" title={t('不管快取，每個來源都重新打一次 API（會用掉額度）')}>
                <input type="checkbox" checked={refresh} onChange={(e) => setRefresh(e.target.checked)} disabled={pending} />
                {t('略過快取')}
              </label>
            ) : null}
            <span className="text-xs text-slate-500">
              {view.lookupsEnabled
                ? willQuery.length
                  ? t('按下後會把這個 IP 送給：{list}', { list: willQuery.map((x) => x.name).join('、') })
                  : t('沒有可用的來源，請先設定金鑰。')
                : t('外部查詢已被關閉（ASA_HUB_IP_LOOKUPS=off）。')}
              {' · '}
              <Link href="/admin?tab=intel" className="text-teal-700 hover:underline dark:text-teal-300">
                {t('設定來源與金鑰')}
              </Link>
            </span>
            {view.queriedAt ? (
              <span className="ml-auto text-xs text-slate-500" title={utc(view.queriedAt)}>
                {t('上次查詢 {at}', { at: since(view.queriedAt, t) })}
              </span>
            ) : null}
          </div>
          {err ? <p className="text-sm text-red-600">{err}</p> : null}
          <ul className="flex flex-wrap gap-2 text-xs">
            {view.providers.map((p) => (
              <li key={p.id} className="rounded-md border border-slate-200 px-2 py-1 dark:border-slate-700">
                <span className="font-medium">{p.name}</span> <span className="text-slate-500">{providerState(p)}</span>
                {p.link ? (
                  <a href={p.link} target="_blank" rel="noreferrer noopener" className="ml-1 text-teal-700 hover:underline dark:text-teal-300">
                    ↗
                  </a>
                ) : null}
              </li>
            ))}
          </ul>
          {queried ? (
            view.merged.length ? (
              <div className="space-y-2">
                <p className="text-sm">
                  {view.total > view.merged.length
                    ? t('外部來源一共看過 {total} 個網域，下面列出其中 {n} 個（多個來源都有的、最近看到的在前）：', { total: view.total, n: view.merged.length })
                    : t('外部來源看過 {n} 個網域：', { n: view.merged.length })}
                </p>
                <ul className="grid gap-x-4 gap-y-1 sm:grid-cols-2 lg:grid-cols-3">
                  {names.map((d) => (
                    <li key={d.name} className="flex min-w-0 items-baseline gap-2 text-sm">
                      <span className="truncate font-mono text-xs" title={d.name}>
                        {d.name}
                      </span>
                      <span className="shrink-0 text-xs text-slate-500" title={d.sources.join('、')}>
                        {d.lastSeen ? since(d.lastSeen, t) : ''}
                        {d.sources.length > 1 ? ` · ${t('{n} 個來源', { n: d.sources.length })}` : ''}
                      </span>
                    </li>
                  ))}
                </ul>
                {view.merged.length > SHOW ? (
                  <button type="button" className="text-sm text-teal-700 hover:underline dark:text-teal-300" onClick={() => setAll(!all)}>
                    {all ? t('收合') : t('顯示全部 {n} 個', { n: view.merged.length })}
                  </button>
                ) : null}
              </div>
            ) : (
              <p className="text-sm text-slate-500">{t('外部來源沒有這個 IP 的網域紀錄。')}</p>
            )
          ) : null}
        </section>
      ) : (
        <p className="text-sm text-slate-500">{t('這是私有或保留位址，不做外部反查。')}</p>
      )}
    </div>
  );
}
