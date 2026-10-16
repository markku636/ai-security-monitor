// 總覽頁的卡片（server component）。
import Link from 'next/link';
import type { Scores } from '@/drizzle/schema';
import { DirectionBadge, ReasonList, VerdictChip } from '@/components/security/Verdict';
import { Card } from '@/components/ui/Card';
import { Gauge } from '@/components/ui/Gauge';
import { ScorePill } from '@/components/ui/Severity';
import { endpoint, since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { listAgents } from '@/lib/queries/agents';
import type { inboundAttackers, listConnections } from '@/lib/queries/connections';
import type { topIntelFeeds } from '@/lib/queries/intel';

const MORE = 'mt-2 inline-block text-sm text-teal-700 hover:underline dark:text-teal-400';

export function ScoreCard({ t, score }: { t: TFn; score: Scores | null }) {
  return (
    <Card title={t('安全分數（車隊平均）')} className="lg:col-span-2">
      <div className="flex flex-wrap justify-around gap-4">
        <Gauge score={score?.overall} label={t('總分')} size={120} />
        <Gauge score={score?.connections} label={t('連線')} />
        <Gauge score={score?.exposure} label={t('曝露')} />
        <Gauge score={score?.vulns} label={t('漏洞')} />
        <Gauge score={score?.hardening} label={t('硬化')} />
      </div>
    </Card>
  );
}

type RiskyResult = Awaited<ReturnType<typeof listConnections>>;

export function RiskyConnectionsCard({ t, risky }: { t: TFn; risky: RiskyResult }) {
  const empty = <p className="text-sm text-slate-500">{t('目前沒有可疑或危險的連線。')}</p>;
  return (
    <Card title={t('危險與可疑連線')}>
      {risky.items.length === 0 ? empty : null}
      <ul className="divide-y divide-slate-100 dark:divide-slate-800">
        {risky.items.map((c) => (
          <li key={c.id} className="flex flex-col gap-1 py-2 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <VerdictChip verdict={c.verdict} t={t} />
              <DirectionBadge direction={c.direction} t={t} />
              <span className="font-mono text-xs">{endpoint(c.remoteIp ?? c.localIp, c.remotePort ?? c.localPort)}</span>
              <span className="text-xs text-slate-500">
                {c.hostname} · {c.processName ?? '—'}
              </span>
            </div>
            <ReasonList reasons={c.reasons} t={t} max={4} />
          </li>
        ))}
      </ul>
      {risky.total > risky.items.length ? (
        <Link href="/connections?verdict=dangerous,suspicious" className={MORE}>
          {t('查看全部 {n} 條 →', { n: risky.total })}
        </Link>
      ) : null}
    </Card>
  );
}

type Feeds = Awaited<ReturnType<typeof topIntelFeeds>>;

export function IntelFeedsCard({ t, feeds }: { t: TFn; feeds: Feeds }) {
  if (!feeds.length) {
    return (
      <Card title={t('情資來源命中（7 天）')}>
        <p className="text-sm text-slate-500">{t('最近 7 天沒有任何情資命中。')}</p>
      </Card>
    );
  }
  return (
    <Card title={t('情資來源命中（7 天）')}>
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-slate-500">
          <tr>
            <th className="py-1">{t('來源')}</th>
            <th className="py-1">{t('指標')}</th>
            <th className="py-1">{t('主機')}</th>
            <th className="py-1">{t('授權')}</th>
          </tr>
        </thead>
        <tbody>
          {feeds.map((f) => (
            <tr key={f.feedId} className="border-t border-slate-100 dark:border-slate-800">
              <td className="py-1.5">
                <a href={f.sourceUrl} target="_blank" rel="noreferrer noopener" className="hover:underline">
                  <span className="font-medium">{f.vendor}</span> <span className="text-slate-500">{f.feedName}</span>
                </a>
              </td>
              <td className="py-1.5 tabular-nums">{f.indicators}</td>
              <td className="py-1.5 tabular-nums">{f.hosts}</td>
              <td className="py-1.5 text-xs text-slate-500">{f.license}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

type Attackers = Awaited<ReturnType<typeof inboundAttackers>>;

export function AttackersCard({ t, attackers }: { t: TFn; attackers: Attackers }) {
  return (
    <Card title={t('對內攻擊來源')}>
      <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
        {attackers.map((a) => (
          <li key={a.remoteIp} className="flex flex-wrap items-center gap-2 py-2">
            <VerdictChip verdict={a.worst} t={t} />
            <span className="font-mono text-xs">{a.remoteIp}</span>
            <span className="text-xs text-slate-500">
              {t('{hosts} 台主機、{conns} 條連線', { hosts: a.hosts, conns: a.conns })}
              {a.country ? ` · ${a.country}` : ''}
            </span>
          </li>
        ))}
      </ul>
      <Link href="/connections?direction=inbound&verdict=dangerous,suspicious" className={MORE}>
        {t('查看對內連線 →')}
      </Link>
    </Card>
  );
}

type AgentList = Awaited<ReturnType<typeof listAgents>>;

export function WorstHostsCard({ t, agents, linkable }: { t: TFn; agents: AgentList; linkable: boolean }) {
  const worst = [...agents].sort((a, b) => (a.score?.overall ?? 101) - (b.score?.overall ?? 101)).slice(0, 6);
  return (
    <Card title={t('分數最低的主機')}>
      <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
        {worst.map((a) => (
          <li key={a.id} className="flex items-center justify-between gap-2 py-2">
            {linkable ? (
              <Link href={`/agents/${encodeURIComponent(a.id)}`} className="font-medium hover:underline">
                {a.hostname}
              </Link>
            ) : (
              <span className="font-medium">{a.hostname}</span>
            )}
            <span className="flex items-center gap-3 text-xs text-slate-500">
              {since(a.lastSeenAt, t)}
              <ScorePill score={a.score?.overall} />
            </span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
