import Link from 'next/link';
import type { ReactNode } from 'react';
import { PrintButton } from '@/components/report/PrintButton';
import { BackButton } from '@/components/ui/BackButton';
import { HostFilter } from '@/components/ui/HostFilter';
import { Hint } from '@/components/ui/Hint';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { getT } from '@/lib/i18n/server';
import type { TFn } from '@/lib/i18n/core';
import { strParam, toQuery } from '@/lib/queries/params';
import { buildReport, MAX_DAYS, parsePeriod, SEVERITIES, sevTotal, type SecurityReport } from '@/lib/report/build';
import { highlights, periodText, sevLabel, todo, verdict } from '@/lib/report/text';

export const dynamic = 'force-dynamic';

const SEC = 'break-inside-avoid rounded-xl border border-slate-200 bg-white p-4 shadow-sm print:shadow-none dark:border-slate-800 dark:bg-slate-900';
const TH = 'px-2 py-1 text-left text-xs font-medium text-slate-500';
const TD = 'px-2 py-1 align-top';
const SEV_TONE: Record<string, string> = {
  critical: 'text-red-700 dark:text-red-400',
  high: 'text-orange-700 dark:text-orange-400',
  medium: 'text-amber-700 dark:text-amber-400',
  low: 'text-sky-700 dark:text-sky-400',
  info: 'text-slate-500',
};

const ymd = (d: Date) => d.toISOString().slice(0, 10);

/** 常用區間：最近 7／30／90 天、本月、上個月。 */
function presets(t: TFn, now = new Date()) {
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const back = (n: number) => ({ from: ymd(new Date(today.getTime() - (n - 1) * 86_400_000)), to: ymd(today) });
  const m0 = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), 1));
  const pm0 = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() - 1, 1));
  return [
    { label: t('最近 7 天'), ...back(7) },
    { label: t('最近 30 天'), ...back(30) },
    { label: t('最近 90 天'), ...back(90) },
    { label: t('本月'), from: ymd(m0), to: ymd(today) },
    { label: t('上個月'), from: ymd(pm0), to: ymd(new Date(m0.getTime() - 86_400_000)) },
  ];
}

function Table({ head, rows, empty }: { head: ReactNode[]; rows: ReactNode[][]; empty: string }) {
  if (!rows.length) return <p className="text-sm text-slate-500">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i} className={TH}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-slate-100 dark:border-slate-800">
              {r.map((c, j) => (
                <td key={j} className={TD}>
                  {c}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Num({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
      <div className="flex items-center text-xs text-slate-500">
        {label}
        {hint ? <Hint text={hint} /> : null}
      </div>
      <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

function Report({ r, t }: { r: SecurityReport; t: TFn }) {
  const p = periodText(r);
  const sevCells = (c: SecurityReport['findings']['newBySev']) => SEVERITIES.map((s) => <span key={s} className={c[s] ? SEV_TONE[s] : 'text-slate-400'}>{c[s]}</span>);
  const nNew = sevTotal(r.findings.newBySev);
  const maxTrend = Math.max(1, ...r.score.trend.map((x) => x.overall));
  return (
    <article className="space-y-4">
      <section className={SEC}>
        <h2 className="text-lg font-semibold">
          {t('資安報告')}
          {r.agent ? ` — ${r.agent.hostname}` : ''}
        </h2>
        <p className="text-sm text-slate-500">
          {t('區間')}：{p.from} ～ {p.to}（{t('{n} 天', { n: r.days })}）· {t('主機')} {r.hosts.total}（{t('有回報 {n} 台', { n: r.hosts.reporting })}）· {t('產生時間')}{' '}
          {r.generatedAt.slice(0, 16).replace('T', ' ')} UTC
        </p>
        <ReportVerdict t={t} r={r} />
        <h3 className="mt-3 text-sm font-semibold">{t('重點')}</h3>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
          {highlights(r, t).map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <Num label={t('平均安全分數')} value={r.score.end ?? '—'} hint={t('期末每台主機最後一份報告的總分平均。')} />
          <Num label={t('新增問題')} value={nNew} />
          <Num label={t('已處理')} value={sevTotal(r.findings.resolvedBySev)} />
          <Num label={t('期末待處理')} value={sevTotal(r.findings.openEndBySev)} />
          <Num label={t('情資命中')} value={r.intel.hits} hint={t('連線或 DNS 查詢碰到威脅情資列名的 IP、網域的次數。')} />
        </div>
      </section>

      <section className={SEC}>
        <h3 className="mb-2 text-sm font-semibold">{t('問題')}</h3>
        <Table
          head={[t('類型'), ...SEVERITIES.map((s) => sevLabel(t, s))]}
          rows={[
            [t('新增'), ...sevCells(r.findings.newBySev)],
            [t('已處理'), ...sevCells(r.findings.resolvedBySev)],
            [t('期末待處理'), ...sevCells(r.findings.openEndBySev)],
          ]}
          empty=""
        />
        <h4 className="mb-1 mt-4 text-xs font-semibold text-slate-500">{t('最常出現的問題')}</h4>
        <Table
          head={[t('嚴重度'), t('問題'), t('次數'), t('主機')]}
          rows={r.findings.topRules.map((x) => [
            <span key="s" className={SEV_TONE[x.severity]}>
              {sevLabel(t, x.severity)}
            </span>,
            <span key="t">
              {x.title}
              <span className="ml-1 font-mono text-xs text-slate-400">{x.rule}</span>
            </span>,
            x.count,
            x.hosts,
          ])}
          empty={t('這段期間沒有新問題。')}
        />
        {r.findings.topNew.length ? (
          <>
            <h4 className="mb-1 mt-4 text-xs font-semibold text-slate-500">{t('新出現的嚴重與高風險問題')}</h4>
            <Table
              head={[t('嚴重度'), t('主機'), t('問題'), t('第一次看到')]}
              rows={r.findings.topNew.map((x) => [
                <span key="s" className={SEV_TONE[x.severity]}>
                  {sevLabel(t, x.severity)}
                </span>,
                <Link key="h" href={`/agents/${encodeURIComponent(x.agentId)}`} className="hover:underline">
                  {x.hostname}
                </Link>,
                x.title,
                <span key="d" className="whitespace-nowrap text-xs text-slate-500">
                  {x.firstSeenAt.slice(0, 16).replace('T', ' ')}
                </span>,
              ])}
              empty=""
            />
          </>
        ) : null}
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className={SEC}>
          <h3 className="mb-2 text-sm font-semibold">{t('安全分數')}</h3>
          <p className="text-sm">
            {t('期初')} <b>{r.score.start ?? '—'}</b> → {t('期末')} <b>{r.score.end ?? '—'}</b>
          </p>
          {r.score.trend.length > 1 ? (
            <div className="mt-2 flex h-24 items-end gap-0.5" aria-label={t('每日平均分數')}>
              {r.score.trend.map((x) => (
                <div key={x.day} className="flex-1 rounded-t bg-teal-500/70" style={{ height: `${(x.overall / maxTrend) * 100}%` }} title={`${x.day}：${x.overall}`} />
              ))}
            </div>
          ) : null}
          {!r.agent ? (
            <>
              <h4 className="mb-1 mt-3 text-xs font-semibold text-slate-500">{t('分數最低的主機')}</h4>
              <Table
                head={[t('主機'), t('總分')]}
                rows={r.score.lowest.map((x) => [
                  <Link key="h" href={`/agents/${encodeURIComponent(x.agentId)}`} className="hover:underline">
                    {x.hostname}
                  </Link>,
                  x.overall,
                ])}
                empty="—"
              />
            </>
          ) : null}
        </section>

        <section className={SEC}>
          <h3 className="mb-2 text-sm font-semibold">{t('威脅情資與連線')}</h3>
          <p className="text-sm">
            {t('情資命中 {n} 筆（{i} 個指標、{h} 台主機）；危險 IP {d} 個、可疑 IP {s} 個。', {
              n: r.intel.hits,
              i: r.intel.indicators,
              h: r.intel.hosts,
              d: r.connections.dangerous,
              s: r.connections.suspicious,
            })}
          </p>
          <Table head={[t('來源'), t('命中')]} rows={r.intel.byFeed.map((x) => [`${x.vendor} ${x.feed}`, x.hits])} empty="" />
          {r.connections.topIps.length ? (
            <div className="mt-2">
              <Table
                head={[t('遠端 IP'), t('判定'), t('次數'), t('國家／組織'), t('備註')]}
                rows={r.connections.topIps.map((x) => [
                  <Link key="ip" href={`/ip/${encodeURIComponent(x.ip)}`} className="font-mono text-xs hover:underline">
                    {x.ip}
                  </Link>,
                  x.verdict === 'dangerous' ? t('危險') : t('可疑'),
                  x.seen,
                  [x.country, x.org].filter(Boolean).join(' '),
                  x.note ?? '',
                ])}
                empty=""
              />
            </div>
          ) : null}
        </section>

        <section className={SEC}>
          <h3 className="mb-2 text-sm font-semibold">DNS</h3>
          <p className="text-sm">
            {t('查詢 {q} 次、{d} 個不同網域、查無此網域 {nx} 次；DNS 告警 {a} 則；防護 DNS 擋下 {b} 次。', {
              q: r.dns.queries.toLocaleString(),
              d: r.dns.domains,
              nx: r.dns.nxdomain,
              a: r.dns.alerts,
              b: r.dns.blocked,
            })}
          </p>
          <Table
            head={[t('被擋最多的網域'), t('次數')]}
            rows={r.dns.topBlocked.map((x) => [
              <Link key="d" href={`/domain/${encodeURIComponent(x.domain)}`} className="font-mono text-xs hover:underline">
                {x.domain}
              </Link>,
              x.count,
            ])}
            empty={t('沒有被擋的查詢（或沒有用防護 DNS）。')}
          />
        </section>

        <section className={SEC}>
          <h3 className="mb-2 text-sm font-semibold">{t('資安事件')}</h3>
          <Table head={[t('規則'), t('次數'), t('主機')]} rows={r.events.byRule.map((x) => [<span key="r" className="font-mono text-xs">{x.rule}</span>, x.count, x.hosts])} empty={t('這段期間沒有資安事件。')} />
          <h4 className="mb-1 mt-3 text-xs font-semibold text-slate-500">{t('封鎖與遠端動作')}</h4>
          <p className="text-sm">{t('遠端動作 {n} 筆、自動回應封鎖 {b} 次。', { n: r.actions.total, b: r.actions.autoBlocks })}</p>
          {r.mitre.length ? (
            <>
              <h4 className="mb-1 mt-3 text-xs font-semibold text-slate-500">MITRE ATT&CK</h4>
              <Table
                head={[t('技術'), t('名稱'), t('問題數')]}
                rows={r.mitre.map((x) => [<span key="i" className="font-mono text-xs">{x.id}</span>, x.name, x.count])}
                empty=""
              />
            </>
          ) : null}
        </section>
      </div>
      <p className="text-xs text-slate-500">{t('由 AI Security Monitor Security Hub 產生；對應 MITRE ATT&CK 與法規僅供參考，不等於稽核或認證。')}</p>
    </article>
  );
}

export default async function ReportPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const fromStr = strParam(sp, 'from', 10);
  const toStr = strParam(sp, 'to', 10);
  const agentId = strParam(sp, 'agent_id', 64);
  const period = parsePeriod(fromStr, toStr);
  const r = period ? await buildReport(getDb(), { ...period, agentId: agentId ?? null }) : null;
  const p = r ? periodText(r) : null;
  const dl = p ? `/api/v1/report${toQuery({ from: p.from, to: p.to, agent_id: agentId })}` : '#';
  return (
    <div className="space-y-4">
      <header className="space-y-2 print:hidden">
        <BackButton fallback="/" />
        <div className="flex flex-wrap items-end justify-between gap-2">
          <div>
            <h1 className="text-xl font-semibold">{t('資安報告')}</h1>
            <p className="text-sm text-slate-500">{t('選一段期間，整理那段時間的安全分數、問題、威脅情資、連線、DNS 與事件；可以列印、存成 PDF 或下載 Markdown。')}</p>
          </div>
          {r ? (
            <div className="flex flex-wrap gap-2">
              <PrintButton />
              <a href={dl} className="rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">
                {t('下載 Markdown')}
              </a>
            </div>
          ) : null}
        </div>
        <form action="/report" className="flex flex-wrap items-end gap-2 text-sm">
          <label className="flex flex-col text-xs text-slate-500">
            {t('開始')}
            <input type="date" name="from" defaultValue={p?.from ?? fromStr ?? ''} className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900" />
          </label>
          <label className="flex flex-col text-xs text-slate-500">
            {t('結束（含當天）')}
            <input type="date" name="to" defaultValue={p?.to ?? toStr ?? ''} className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900" />
          </label>
          {agentId ? <input type="hidden" name="agent_id" value={agentId} /> : null}
          <button type="submit" className="rounded-md border border-teal-600 px-3 py-1 text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950">
            {t('產生報告')}
          </button>
          <span className="flex flex-wrap gap-1">
            {presets(t).map((x) => (
              <Link
                key={x.label}
                href={`/report${toQuery({ from: x.from, to: x.to, agent_id: agentId })}`}
                className={`rounded-full border px-2 py-0.5 text-xs ${p && p.from === x.from && p.to === x.to ? 'border-teal-600 bg-teal-600 text-white' : 'border-slate-300 hover:border-teal-600 dark:border-slate-700'}`}
              >
                {x.label}
              </Link>
            ))}
          </span>
        </form>
        <HostFilter t={t} action="/report" current={agentId} keep={{ from: p?.from, to: p?.to }} />
      </header>
      {r ? <Report r={r} t={t} /> : <p className="text-sm text-red-600">{t('期間不正確（開始要早於結束、最長 {n} 天）。', { n: MAX_DAYS })}</p>}
    </div>
  );
}

/** 報告開頭：一句話結論（顏色依輕重）與「建議你先做」。 */
function ReportVerdict({ t, r }: { t: TFn; r: Parameters<typeof verdict>[0] }) {
  const v = verdict(r, t);
  const steps = todo(r, t);
  const tone =
    v.tone === 'bad'
      ? 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-100'
      : v.tone === 'warn'
        ? 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100'
        : 'border-green-300 bg-green-50 text-green-900 dark:border-green-800 dark:bg-green-950/40 dark:text-green-100';
  return (
    <div className={`mt-3 rounded-lg border p-3 ${tone}`}>
      <p className="font-medium">{v.text}</p>
      {steps.length ? (
        <>
          <h3 className="mt-2 text-sm font-semibold">{t('建議你先做')}</h3>
          <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm">
            {steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </>
      ) : null}
    </div>
  );
}
