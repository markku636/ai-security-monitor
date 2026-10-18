import Link from 'next/link';
import { DnsHowTo } from '@/components/dns/DnsHowTo';
import { DnsListQuickAdd } from '@/components/dns/DnsListQuickAdd';
import { FindingsTable } from '@/components/security/FindingsTable';
import { Badge } from '@/components/ui/Badge';
import { Card, Stat } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { FilterChip, FilterRow, SearchBox } from '@/components/ui/Filters';
import { Hint, Term } from '@/components/ui/Hint';
import { HostFilter } from '@/components/ui/HostFilter';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { getProtect, listServers, resolverStats } from '@/lib/dns/protect';
import { since } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import type { TFn } from '@/lib/i18n/core';
import { collectorStatus, dnsStats, newDomains, recentQueries, topDomains } from '@/lib/queries/dns';
import { listFindings, toFindingView } from '@/lib/queries/findings';
import { clampInt, strParam, toQuery } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

const DAY_CHOICES = [1, 7, 30];
const QTYPES: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS' };

function qtype(n: number): string {
  return QTYPES[n] ?? `TYPE${n}`;
}

function sourceLabel(t: TFn, s: string | null): string {
  switch (s) {
    case 'etw':
      return t('Windows 即時事件');
    case 'eventlog':
      return t('Windows 事件紀錄');
    case 'cache':
      return t('DNS 快取快照');
    case 'packet':
      return t('監聽 53 port');
    case null:
      return t('沒有可用來源');
    default:
      return s;
  }
}

export default async function DnsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const days = clampInt(sp, 'days', 1, 1, 90);
  const agentId = strParam(sp, 'agent_id', 64);
  const q = strParam(sp, 'q', 100);
  const nx = strParam(sp, 'nx', 1) === '1';
  const [stats, top, fresh, recent, collectors, open, servers, protect, guard] = await Promise.all([
    dnsStats(days, agentId),
    topDomains(days, agentId, 20),
    newDomains(24, 30),
    recentQueries({ agentId, q, nx, limit: 100 }),
    collectorStatus(agentId),
    listFindings({ agentId, status: ['open', 'acked'], severity: [], scanner: ['dns'], limit: 20, offset: 0 }),
    listServers(getDb()),
    getProtect(getDb()),
    resolverStats(getDb(), 24),
  ]);
  const online = servers.filter((s) => s.online).length;
  const nxPct = stats.queries ? Math.round((stats.nxdomain / stats.queries) * 1000) / 10 : 0;
  const keep = { days: String(days), agent_id: agentId };
  const empty = !stats.queries && !recent.length && !open.items.length;
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">{t('DNS')}</h1>
          <p className="text-sm text-slate-500">
            {t('每台電腦查了哪些網域、是哪個程式查的、哪些可疑。DNS 紀錄等於上網紀錄，只有管理員看得到。')}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={`/ai${toQuery({ scope: 'dns', agent_id: agentId })}`}
            className="rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950"
          >
            {t('請 AI 解讀 DNS')}
          </a>
          <FilterRow label={t('期間')}>
            {DAY_CHOICES.map((d) => (
              <FilterChip key={d} href={`/dns${toQuery({ days: d, agent_id: agentId, q, nx: nx ? '1' : undefined })}`} active={d === days}>
                {d === 1 ? t('24 小時') : t('{n} 天', { n: d })}
              </FilterChip>
            ))}
          </FilterRow>
        </div>
      </header>
      <HostFilter t={t} action="/dns" current={agentId} keep={{ days, q, nx: nx ? '1' : undefined }} />
      <DnsHowTo t={t} open={empty} />
      <DnsListQuickAdd blocked={protect.block.length} allowed={protect.allow.length} />
      {empty ? (
        <EmptyState title={t('還沒有 DNS 紀錄')}>
          {t('主機的背景服務會即時記錄 DNS 查詢並每分鐘上傳（需要 ai-security-monitor 0.6 以上；Windows 以系統服務執行才看得到是哪個程式查的）。')}
        </EmptyState>
      ) : null}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label={t('查詢次數')} value={stats.queries.toLocaleString()} hint={t('{n} 台主機', { n: stats.hosts })} />
        <Stat
          label={
            <>
              {t('不同網域')} <Hint text={t('依「可註冊網域」計算：a.b.example.co.uk 算成 example.co.uk，同一家的子網域合成一個。')} />
            </>
          }
          value={stats.domains.toLocaleString()}
        />
        <Stat
          label={
            <>
              <Term hint={t('查無此網域。偶爾出現很正常；同一個程式短時間大量出現，常是亂數產生網域找控制伺服器的惡意程式。')}>NXDOMAIN</Term>
            </>
          }
          value={`${nxPct}%`}
          hint={t('{n} 次', { n: stats.nxdomain.toLocaleString() })}
        />
        <Stat label={t('DNS 告警（待處理）')} value={open.total} hint={<Link className="hover:underline" href={`/findings${toQuery({ scanner: 'dns', agent_id: agentId })}`}>{t('看全部')}</Link>} />
      </div>
      <p className="flex flex-wrap items-center gap-x-2 text-sm text-slate-600 dark:text-slate-300">
        <span className="font-medium">
          {t('防護 DNS')}
          <Hint text={t('給整個區網用的 DNS 伺服器：把電腦、手機、IoT 的 DNS 指到它，查到威脅情資列名的網域就擋掉（回「查無此網域」），其他照常經加密 DNS 轉送並快取。')} />
        </span>
        {servers.length ? (
          <span>
            {t('{n} 台在線', { n: online })} · {protect.enabled ? t('封鎖中') : t('封鎖已關閉（只轉送）')} ·{' '}
            {t('24 小時擋了 {b} 次、{c} 個裝置在用', { b: guard.blocked.toLocaleString(), c: guard.clients })}
          </span>
        ) : (
          <span className="text-slate-500">{t('還沒有防護 DNS 連上來')}</span>
        )}
        <span>
          ·{' '}
          <Link className="hover:underline" href="/admin?tab=dns">
            {t('黑名單 {n} 筆', { n: protect.block.length })}
          </Link>
        </span>
        <Link className="text-teal-700 hover:underline dark:text-teal-400" href="/admin?tab=dns">
          {t('設定 →')}
        </Link>
      </p>
      {open.items.length ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">
            {t('DNS 告警')}{' '}
            <Hint
              text={t('情資列名的網域、DNS 通道（把資料編碼進大量又長又亂的子網域送出去）、DGA（亂數產生的網域）、大量查無此網域、程式自己改走加密 DNS（DoH）繞過公司 DNS、反向通道服務。')}
            />
          </h2>
          <FindingsTable rows={open.items.map(toFindingView)} canWrite showHost={!agentId} />
        </section>
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={t('查詢最多的網域')}>
          {top.length ? (
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-500">
                <tr>
                  <th className="py-1.5 pr-3">{t('網域')}</th>
                  <th className="py-1.5 pr-3 text-right">{t('次數')}</th>
                  <th className="py-1.5 pr-3 text-right">{t('主機')}</th>
                  <th className="py-1.5 pr-3 text-right">NXDOMAIN</th>
                </tr>
              </thead>
              <tbody>
                {top.map((d) => (
                  <tr key={d.registrable} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="py-1.5 pr-3">
                      <Link className="font-mono text-xs hover:underline" href={`/domain/${encodeURIComponent(d.registrable)}`}>
                        {d.registrable}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{d.queries.toLocaleString()}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{d.hosts}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{d.nxdomain ? d.nxdomain.toLocaleString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-slate-500">{t('這段期間沒有資料')}</p>
          )}
        </Card>
        <Card
          title={
            <>
              {t('新出現的網域（24 小時）')} <Hint text={t('所有主機以前都沒查過、最近 24 小時第一次出現的網域。大多是正常的新網站；不認得的程式查的才值得點進去看。')} />
            </>
          }
        >
          {fresh.length ? (
            <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
              {fresh.map((d) => (
                <li key={d.registrable} className="flex flex-wrap items-baseline justify-between gap-2 py-1.5">
                  <Link className="font-mono text-xs hover:underline" href={`/domain/${encodeURIComponent(d.registrable)}`}>
                    {d.registrable}
                  </Link>
                  <span className="text-xs text-slate-500">
                    {d.hostname ?? '—'}
                    {d.process ? ` · ${d.process}` : ''} · {since(d.firstSeenAt, t)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-500">{t('最近 24 小時沒有新網域')}</p>
          )}
        </Card>
      </div>
      <Card title={t('最近的查詢')}>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <SearchBox t={t} action="/dns" q={q} keep={{ ...keep, nx: nx ? '1' : undefined }} placeholder={t('網域或程式，例：example.com、powershell')} />
          <FilterRow label={t('結果')}>
            <FilterChip href={`/dns${toQuery({ ...keep, q })}`} active={!nx}>
              {t('全部')}
            </FilterChip>
            <FilterChip href={`/dns${toQuery({ ...keep, q, nx: '1' })}`} active={nx}>
              {t('只看查無此網域')}
            </FilterChip>
          </FilterRow>
        </div>
        {recent.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-500">
                <tr>
                  <th className="py-1.5 pr-3">{t('時間')}</th>
                  {!agentId ? <th className="py-1.5 pr-3">{t('主機')}</th> : null}
                  <th className="py-1.5 pr-3">{t('程式')}</th>
                  <th className="py-1.5 pr-3">{t('網域')}</th>
                  <th className="py-1.5 pr-3">{t('類型')}</th>
                  <th className="py-1.5 pr-3">{t('結果')}</th>
                  <th className="py-1.5 pr-3 text-right">{t('次數')}</th>
                  <th className="py-1.5 pr-3">{t('解析到')}</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((r, i) => (
                  <tr key={i} className="border-t border-slate-100 align-top dark:border-slate-800">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-xs text-slate-500">{since(r.ts, t)}</td>
                    {!agentId ? (
                      <td className="py-1.5 pr-3 text-xs">
                        <Link className="hover:underline" href={`/dns${toQuery({ days, agent_id: r.agentId })}`}>
                          {r.hostname}
                        </Link>
                      </td>
                    ) : null}
                    <td className="py-1.5 pr-3 text-xs">{r.process || <span className="text-slate-400">—</span>}</td>
                    <td className="py-1.5 pr-3">
                      <Link className="break-all font-mono text-xs hover:underline" href={`/domain/${encodeURIComponent(r.name)}`}>
                        {r.name}
                      </Link>
                    </td>
                    <td className="py-1.5 pr-3 text-xs">{qtype(r.qtype)}</td>
                    <td className="py-1.5 pr-3 text-xs">{r.rcode === 'NOERROR' ? r.rcode : <Badge tone={r.rcode === 'NXDOMAIN' ? 'warn' : 'neutral'}>{r.rcode}</Badge>}</td>
                    <td className="py-1.5 pr-3 text-right text-xs tabular-nums">{r.count}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {(r.answers ?? []).slice(0, 2).map((ip) => (
                        <Link key={ip} className="mr-1 hover:underline" href={`/ip/${encodeURIComponent(ip)}`}>
                          {ip}
                        </Link>
                      ))}
                      {(r.answers ?? []).length > 2 ? <span className="text-slate-400">+{r.answers.length - 2}</span> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-slate-500">{t('沒有符合的查詢（原始紀錄保留 7 天）')}</p>
        )}
      </Card>
      <Card title={t('各主機的 DNS 監看')}>
        <table className="w-full text-left text-sm">
          <thead className="text-xs text-slate-500">
            <tr>
              <th className="py-1.5 pr-3">{t('主機')}</th>
              <th className="py-1.5 pr-3">{t('狀態')}</th>
              <th className="py-1.5 pr-3">
                {t('資料來源')} <Hint text={t('Windows 以系統服務執行時用即時事件、知道是哪個程式查的；沒有系統管理員權限時改看 DNS 快取（不知道程式）。Linux／macOS 以 root 監聽 53 port。')} />
              </th>
              <th className="py-1.5 pr-3">{t('最後一筆')}</th>
            </tr>
          </thead>
          <tbody>
            {collectors.map((c) => (
              <tr key={c.agentId} className="border-t border-slate-100 dark:border-slate-800">
                <td className="py-1.5 pr-3">
                  <Link className="hover:underline" href={`/dns${toQuery({ days, agent_id: c.agentId })}`}>
                    {c.hostname}
                  </Link>
                </td>
                <td className="py-1.5 pr-3 text-xs">
                  {!c.at ? (
                    <span className="text-slate-400">{t('尚未回報（需要新版 ai-security-monitor）')}</span>
                  ) : c.running ? (
                    <Badge tone="ok">{t('執行中')}</Badge>
                  ) : (
                    <Badge tone="warn">{t('沒有在跑')}</Badge>
                  )}
                </td>
                <td className="py-1.5 pr-3 text-xs">
                  {c.at ? sourceLabel(t, c.source) : '—'}
                  {c.at && c.source && !c.hasProcess ? <span className="text-slate-400"> · {t('看不到程式')}</span> : null}
                </td>
                <td className="py-1.5 pr-3 text-xs text-slate-500">{c.lastEventAt ? since(c.lastEventAt, t) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
