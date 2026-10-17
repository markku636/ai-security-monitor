'use client';

// IP 分析頁的「外部威脅情資」：風險分數與理由、各來源命中 x/N、欄位明細、原始回應。
// 只有按「查詢外部情資」才會把 IP 送給第三方；其餘時間只顯示快取。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition, type ReactNode } from 'react';
import { apiPost } from '@/lib/api-client';
import { since, utc } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { useT } from '@/lib/i18n/client';
import type { IpIntelView, ProviderView, RiskLevel, ScoreReason, SkipReason } from '@/lib/ipintel/types';

const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SUB = 'text-xs font-semibold text-slate-500';

const LEVEL_STYLE: Record<RiskLevel, { chip: string; num: string }> = {
  critical: { chip: 'bg-red-600 text-white', num: 'text-red-600 dark:text-red-400' },
  high: { chip: 'bg-orange-500 text-white', num: 'text-orange-600 dark:text-orange-400' },
  medium: { chip: 'bg-amber-400 text-amber-950', num: 'text-amber-600 dark:text-amber-400' },
  low: { chip: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300', num: 'text-green-700 dark:text-green-400' },
};

function levelText(t: TFn, l: RiskLevel) {
  return { critical: t('極高風險'), high: t('高風險'), medium: t('中風險'), low: t('低風險') }[l];
}

function levelAdvice(t: TFn, l: RiskLevel) {
  return {
    critical: t('75–100 分：建議人工確認後封鎖'),
    high: t('50–74 分：建議人工審查，限制這個 IP 的存取'),
    medium: t('25–49 分：持續觀察，搭配連線紀錄交叉判讀'),
    low: t('0–24 分：目前不需處理'),
  }[l];
}

function reasonText(t: TFn, r: ScoreReason): string {
  const p = r.params ?? {};
  switch (r.key) {
    case 'spamhaus':
      return t('列在 Spamhaus DROP（被劫持或專門作惡的網段）');
    case 'ipsum':
      return t('列在 IPsum（多份黑名單都有它）');
    case 'firehol':
      return t('列在 FireHOL Level 1');
    case 'blocklist':
      return t('列在其他黑名單：{feeds}', { feeds: p.feeds ?? '' });
    case 'tor':
      return t('Tor 出口節點（匿名網路的出口）');
    case 'abuseipdb':
      return t('AbuseIPDB 濫用信心分 {score}（{reports} 筆回報）', { score: p.score ?? 0, reports: p.reports ?? 0 });
    case 'greynoise_malicious':
      return t('GreyNoise 判定為惡意（實際觀察到攻擊行為）');
    case 'greynoise_benign':
      return p.name ? t('GreyNoise 判定為良性：{name}', { name: p.name }) : t('GreyNoise 判定為良性（已知的合法服務或掃描器）');
    case 'proxy':
      return t('是 Proxy／VPN（{type}）', { type: p.type ?? '' });
    case 'datacenter':
      return t('來自資料中心／雲端主機，不是一般家用網路');
    case 'rule_spamhaus':
      return t('規則：Spamhaus DROP 命中，分數至少 {n}', { n: p.n ?? 0 });
    case 'rule_abuseipdb_high':
      return t('規則：AbuseIPDB 信心分 ≥ 90，分數至少 {n}', { n: p.n ?? 0 });
    case 'rule_tor':
      return t('規則：Tor 出口節點，分數至少 {n}', { n: p.n ?? 0 });
    default:
      return r.key;
  }
}

function skipText(t: TFn, r: SkipReason | undefined): string {
  switch (r) {
    case 'no-api-key':
      return t('沒有設定金鑰');
    case 'quota-exhausted':
      return t('今天的額度用完了');
    case 'timeout':
      return t('逾時');
    case 'http-error':
      return t('連線或伺服器錯誤');
    case 'parse-error':
      return t('回應格式看不懂');
    case 'disabled':
      return t('已停用');
    case 'unsupported':
      return t('不支援 IPv6');
    case 'not-public':
      return t('不是公網 IP');
    default:
      return t('失敗');
  }
}

/** 這個來源為什麼這次不會查（回 null＝會查）。 */
function notQueryReason(t: TFn, p: ProviderView, v6: boolean): string | null {
  if (!p.enabled) return skipText(t, 'disabled');
  if (p.key === 'required' && !p.configured) return skipText(t, 'no-api-key');
  if (v6 && p.id === 'greynoise') return skipText(t, 'unsupported');
  return null;
}

function usageText(t: TFn, u: string | null | undefined) {
  if (!u) return '—';
  return (
    ({ datacenter: t('資料中心／主機商'), isp: t('住宅／固網 ISP'), mobile: t('行動網路'), business: t('企業'), edu: t('學術'), gov: t('政府') } as Record<string, string>)[u] ?? u
  );
}

function greynoiseText(t: TFn, c: string | null | undefined) {
  if (!c) return '—';
  return (
    ({ benign: t('良性（已審核的合法服務）'), malicious: t('惡意（觀察到攻擊）'), suspicious: t('可疑'), unknown: t('沒看過它在網路上掃描') } as Record<string, string>)[c] ?? c
  );
}

function Tri({ v, t }: { v: boolean | null | undefined; t: TFn }) {
  if (v == null) return <span className="text-slate-400">{t('未查詢')}</span>;
  return v ? <span className="font-semibold text-red-600 dark:text-red-400">{t('是')}</span> : <span>{t('否')}</span>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-slate-100 py-1.5 dark:border-slate-800">
      <dt className="text-xs text-slate-500" title={hint}>
        {label}
        {hint ? <span className="ml-1 cursor-help text-slate-400">ⓘ</span> : null}
      </dt>
      <dd className="text-sm break-all">{children}</dd>
    </div>
  );
}

function ExtLink({ href, children }: { href: string | null; children: ReactNode }) {
  if (!href) return <>{children}</>;
  return (
    <a href={href} target="_blank" rel="noreferrer noopener" className="text-teal-700 hover:underline dark:text-teal-300">
      {children}
    </a>
  );
}

function Pill({ name, hit, href, title, t }: { name: string; hit: boolean | null; href: string | null; title?: string; t: TFn }) {
  const cls =
    hit === null
      ? 'border-slate-300 text-slate-500 dark:border-slate-700'
      : hit
        ? 'border-red-300 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-300'
        : 'border-green-300 bg-green-50 text-green-800 dark:border-green-800 dark:bg-green-950/40 dark:text-green-300';
  const label = hit === null ? t('未查詢') : hit ? t('命中') : t('無訊號');
  const body = (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs ${cls}`} title={title}>
      <span className="font-medium">{name}</span>
      <span className="opacity-80">{label}</span>
    </span>
  );
  return href ? (
    <a href={href} target="_blank" rel="noreferrer noopener" className="hover:opacity-80">
      {body}
    </a>
  ) : (
    body
  );
}

export function IpThreatIntel({ view }: { view: IpIntelView }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [refresh, setRefresh] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const v6 = view.ip.includes(':');

  if (!view.isPublic) {
    return <p className="text-sm text-slate-500">{t('這是私有或保留位址（內網、本機、文件範例等），不查外部情資。')}</p>;
  }

  const willQuery = view.providers.filter((p) => p.willQuery);
  const p = view.profile;
  const by = Object.fromEntries(view.providers.map((x) => [x.id, x])) as Record<string, ProviderView>;
  const threatPills = view.providers.filter((x) => ['abuseipdb', 'greynoise', 'proxycheck'].includes(x.id));
  const evaluated = threatPills.filter((x) => x.hit !== null).length + 1;
  const hits = threatPills.filter((x) => x.hit).length + (view.localHits.length ? 1 : 0);
  const problems = view.providers
    .map((x) => {
      const why = x.result && !x.result.ok ? skipText(t, x.result.reason) : x.result?.detail ? x.result.detail : !x.result ? notQueryReason(t, x, v6) : null;
      return why ? { id: x.id, name: x.name, why } : null;
    })
    .filter((x): x is { id: ProviderView['id']; name: string; why: string } => x !== null);
  const maxAbs = Math.max(1, ...(view.score?.reasons ?? []).map((r) => Math.abs(r.contribution ?? 0)));

  const run = () => {
    setErr(null);
    start(async () => {
      const r = await apiPost<{ error?: string }>('/api/v1/ip-intel', { ip: view.ip, refresh });
      if (!r.ok) {
        setErr(r.data.error === 'lookups_disabled' ? t('外部查詢已被關閉（ASA_HUB_IP_LOOKUPS=off）。') : t('查詢失敗（HTTP {n}）', { n: r.status }));
        return;
      }
      setRefresh(false);
      router.refresh();
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className={BTN} onClick={run} disabled={pending || !view.lookupsEnabled || !willQuery.length}>
          {pending ? t('查詢中…') : view.queriedAt ? t('重新查詢外部情資') : t('查詢外部情資')}
        </button>
        {view.queriedAt ? (
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

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
          {view.score ? (
            <>
              <div className="flex items-end gap-2">
                <span className={`text-6xl font-bold tabular-nums ${LEVEL_STYLE[view.score.level].num}`}>{view.score.score}</span>
                <span className="mb-2 text-sm text-slate-500">/ 100 {t('風險分數')}</span>
              </div>
              <span className={`mt-2 inline-block rounded px-2 py-0.5 text-sm font-semibold ${LEVEL_STYLE[view.score.level].chip}`}>
                {levelText(t, view.score.level)}
              </span>
              <p className="mt-3 rounded-md bg-slate-50 p-2 text-sm dark:bg-slate-800/60">{levelAdvice(t, view.score.level)}</p>
              <p className="mt-3 text-xs text-slate-500">{t('分數只是參考：高分不等於確定是惡意，低分也不保證安全，請搭配連線紀錄判斷。')}</p>
            </>
          ) : (
            <>
              <div className="text-6xl font-bold text-slate-300 dark:text-slate-700">—</div>
              <p className="mt-3 text-sm text-slate-500">{t('還沒查詢外部情資，也沒有黑名單命中。按「查詢外部情資」取得分數。')}</p>
              <p className="mt-2 text-xs text-slate-500">{t('沒有命中不代表安全。')}</p>
            </>
          )}
        </div>

        <div className="rounded-lg border border-slate-200 p-4 lg:col-span-2 dark:border-slate-800">
          <h3 className={`${SUB} mb-2`}>{t('分數怎麼來的')}</h3>
          {view.score?.reasons.length ? (
            <ul className="space-y-2">
              {view.score.reasons.map((r, i) => {
                const c = r.contribution;
                const width = c == null ? 100 : (Math.abs(c) / maxAbs) * 100;
                const color = r.kind === 'rule' ? 'bg-slate-400 dark:bg-slate-600' : (c ?? 0) < 0 ? 'bg-emerald-500' : 'bg-orange-500';
                return (
                  <li key={i}>
                    <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
                      <span>{reasonText(t, r)}</span>
                      <span className="text-xs tabular-nums text-slate-500">
                        {c == null ? t('下限規則') : `${c > 0 ? '+' : ''}${c} ${t('分')}`}
                      </span>
                    </div>
                    <div className="mt-1 h-2 rounded bg-slate-100 dark:bg-slate-800">
                      <div className={`h-2 rounded ${color}`} style={{ width: `${Math.max(3, width)}%` }} />
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="text-sm text-slate-500">{view.score ? t('沒有任何風險訊號。') : '—'}</p>
          )}
        </div>
      </div>

      <div>
        <h3 className={`${SUB} mb-2`}>
          {t('命中 {x} / {n} 個情資來源', { x: hits, n: evaluated })}
        </h3>
        <div className="flex flex-wrap gap-2">
          <Pill
            name={t('ai-security-monitor 黑名單')}
            hit={view.localHits.length > 0}
            href={null}
            title={view.localHits.length ? view.localHits.map((h) => `${h.vendor} · ${h.feedName}`).join('\n') : t('各主機同步的黑名單（FireHOL、Spamhaus、Tor 出口…）都沒有這個 IP')}
            t={t}
          />
          {threatPills.map((x) => (
            <Pill key={x.id} name={x.name} hit={x.hit} href={x.link} title={x.hit === null ? (notQueryReason(t, x, v6) ?? t('還沒查詢')) : undefined} t={t} />
          ))}
        </div>
        {view.localHits.length ? (
          <ul className="mt-2 space-y-0.5 text-xs text-slate-500">
            {view.localHits.map((h) => (
              <li key={h.feedId}>
                <a href={h.sourceUrl} target="_blank" rel="noreferrer noopener" className="hover:underline">
                  {h.vendor} · {h.feedName}
                </a>{' '}
                · {t('信心 {n}%', { n: h.confidence })}
              </li>
            ))}
          </ul>
        ) : null}
      </div>

      <dl className="grid gap-x-6 sm:grid-cols-2 lg:grid-cols-3">
        <Field label={t('國家／城市')}>{[p.country, p.city].filter(Boolean).join(' / ') || '—'}</Field>
        <Field label="ASN" hint={t('自治系統編號：這個 IP 屬於哪個網路業者')}>
          {p.asn ? <ExtLink href={`https://ipinfo.io/AS${p.asn}`}>AS{p.asn}</ExtLink> : '—'}
        </Field>
        <Field label={t('網路業者／組織')}>{p.asnOrg ?? p.isp ?? '—'}</Field>
        <Field label={t('用途類型')} hint={t('AbuseIPDB 對這個網段的分類：資料中心、家用 ISP、行動網路、企業…')}>
          {usageText(t, p.usageType)}
        </Field>
        <Field label={t('資料中心')} hint={t('雲端主機或機房的 IP。一般使用者很少從這裡連線，攻擊者常用')}>
          <Tri v={p.isDatacenter} t={t} />
        </Field>
        <Field label="Proxy" hint={t('代理伺服器：真正的來源藏在後面')}>
          <Tri v={p.isProxy} t={t} />
        </Field>
        <Field label="VPN" hint={t('VPN 出口：真正的使用者藏在後面')}>
          <Tri v={p.isVpn} t={t} />
        </Field>
        <Field label="Tor" hint={t('Tor 匿名網路的出口節點')}>
          <Tri v={view.localHits.some((h) => h.feedId === 'tor-exits') || p.isTor === true ? true : (p.isTor ?? (by.abuseipdb?.result?.ok ? false : null))} t={t} />
        </Field>
        <Field label={t('反解主機名')} hint={t('PTR 紀錄：用 IP 反查出來的主機名稱')}>
          {p.hostname ?? (by.rdns?.result?.ok ? t('沒有') : '—')}
        </Field>
        <Field label="FCrDNS" hint={t('正反解一致：主機名稱再查回來是不是同一個 IP。一致的通常是正規服務')}>
          {p.fcrdns == null ? '—' : p.fcrdns ? t('一致') : <span className="text-amber-700 dark:text-amber-400">{t('不一致')}</span>}
        </Field>
        <Field label={t('AbuseIPDB 信心分')} hint={t('0–100：最近 90 天被回報濫用的可信程度')}>
          {p.abuseScore != null ? (
            <ExtLink href={by.abuseipdb?.link ?? null}>
              {p.abuseScore} / 100 · {t('{n} 筆回報', { n: p.abuseReports ?? 0 })}
            </ExtLink>
          ) : (
            '—'
          )}
        </Field>
        <Field label={t('GreyNoise 分類')} hint={t('GreyNoise 觀察全網掃描流量：良性掃描器、惡意攻擊或沒見過')}>
          {p.greynoiseClass ? (
            <ExtLink href={by.greynoise?.link ?? null}>
              {greynoiseText(t, p.greynoiseClass)}
              {p.greynoiseName ? ` · ${p.greynoiseName}` : ''}
            </ExtLink>
          ) : (
            '—'
          )}
        </Field>
        <Field label={t('proxycheck 風險')} hint={t('proxycheck.io 的風險分數 0–100')}>
          {p.proxyRisk != null ? <ExtLink href={by.proxycheck?.link ?? null}>{p.proxyRisk} / 100</ExtLink> : '—'}
        </Field>
      </dl>

      {problems.length ? (
        <div>
          <h3 className={`${SUB} mb-1`}>{t('這次沒查或失敗的來源')}</h3>
          <ul className="space-y-0.5 text-xs text-slate-500">
            {problems.map((x) => (
              <li key={x.id}>
                <span className="font-medium">{x.name}</span>：{x.why}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {view.providers.some((x) => x.result?.raw != null) ? (
        <details className="text-xs">
          <summary className="cursor-pointer text-slate-500">{t('原始回應')}</summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded-md bg-slate-50 p-3 dark:bg-slate-950">
            {JSON.stringify(Object.fromEntries(view.providers.filter((x) => x.result?.raw != null).map((x) => [x.id, x.result?.raw])), null, 2)}
          </pre>
        </details>
      ) : null}
    </div>
  );
}
