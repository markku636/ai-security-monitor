// 總覽頁的卡片（server component）。
import Link from 'next/link';
import type { Scores } from '@/drizzle/schema';
import { IpLink } from '@/components/security/IpLink';
import { DirectionBadge, ReasonList, VerdictChip } from '@/components/security/Verdict';
import { Card } from '@/components/ui/Card';
import { Gauge } from '@/components/ui/Gauge';
import { CountryFlag } from '@/components/ui/CountryFlag';
import { Hint } from '@/components/ui/Hint';
import { ScorePill } from '@/components/ui/Severity';
import { endpoint, since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { IpRisk } from '@/lib/ipintel/types';
import type { listAgents } from '@/lib/queries/agents';
import type { inboundAttackers, listConnections } from '@/lib/queries/connections';
import type { topIntelFeeds } from '@/lib/queries/intel';
import { SCORE_KEYS, scoreHints, scoreLabels } from './scoreHints';

const MORE = 'mt-2 inline-block text-sm text-teal-700 hover:underline dark:text-teal-400';

export function ScoreCard({ t, score }: { t: TFn; score: Scores | null }) {
  const labels = scoreLabels(t);
  const hints = scoreHints(t);
  return (
    <Card
      title={
        <>
          {t('安全分數（所有主機平均）')}
          <Hint text={hints.card} />
        </>
      }
      className="lg:col-span-2"
    >
      <div className="flex flex-wrap justify-around gap-4">
        {SCORE_KEYS.map((k) => (
          <Gauge key={k} score={score?.[k]} label={labels[k]} hint={hints[k]} size={104} emphasis={k === 'overall'} />
        ))}
      </div>
    </Card>
  );
}

type RiskyResult = Awaited<ReturnType<typeof listConnections>>;

/** 同一台主機、同一個行程連到同一個遠端（同判定）只列一次，標出條數。 */
function groupRisky(items: RiskyResult['items'], max: number) {
  const groups = new Map<string, { c: RiskyResult['items'][number]; n: number }>();
  for (const c of items) {
    const k = [c.agentId, c.verdict, c.direction, c.remoteIp ?? c.localIp, c.remotePort ?? c.localPort, c.processName ?? ''].join('|');
    const g = groups.get(k);
    if (g) g.n += 1;
    else groups.set(k, { c, n: 1 });
  }
  return [...groups.values()].slice(0, max);
}

export function RiskyConnectionsCard({ t, risky, risks = {} }: { t: TFn; risky: RiskyResult; risks?: Record<string, IpRisk> }) {
  const empty = <p className="text-sm text-slate-500">{t('目前沒有可疑或危險的連線。')}</p>;
  const rows = groupRisky(risky.items, 8);
  return (
    <Card
      title={
        <>
          {t('危險與可疑連線')}
          <Hint text={t('危險＝連到威脅情資高信心列名的位址（例如惡意程式的控制伺服器）；可疑＝低信心情資或行為異常，可能是誤報，值得看一下。')} />
        </>
      }
    >
      {risky.items.length === 0 ? empty : null}
      <ul className="divide-y divide-slate-100 dark:divide-slate-800">
        {rows.map(({ c, n }) => (
          <li key={c.id} className="flex flex-col gap-1 py-2 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <VerdictChip verdict={c.verdict} t={t} />
              <DirectionBadge direction={c.direction} t={t} />
              <IpLink ip={c.remoteIp} className="font-mono text-xs" risk={c.remoteIp ? risks[c.remoteIp] : undefined} t={t}>
                {endpoint(c.remoteIp ?? c.localIp, c.remotePort ?? c.localPort)}
              </IpLink>
              <span className="text-xs text-slate-500">
                {c.hostname} · {c.processName ?? '—'}
              </span>
              {n > 1 ? <span className="text-xs text-slate-500">{t('× {n} 條連線', { n })}</span> : null}
            </div>
            <ReasonList reasons={c.reasons} t={t} max={4} />
          </li>
        ))}
      </ul>
      {risky.total > rows.length ? (
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
      <Card
      title={
        <>
          {t('情資來源命中（7 天）')}
          <Hint text={t('最近 7 天，各主機的連線對到哪些威脅情資清單（例如惡意 IP 黑名單）、對到幾個指標、影響幾台主機。')} />
        </>
      }
    >
        <p className="text-sm text-slate-500">{t('最近 7 天沒有任何情資命中。')}</p>
      </Card>
    );
  }
  return (
    <Card
      title={
        <>
          {t('情資來源命中（7 天）')}
          <Hint text={t('最近 7 天，各主機的連線對到哪些威脅情資清單（例如惡意 IP 黑名單）、對到幾個指標、影響幾台主機。')} />
        </>
      }
    >
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

export function AttackersCard({ t, attackers, risks = {} }: { t: TFn; attackers: Attackers; risks?: Record<string, IpRisk> }) {
  return (
    <Card
      title={
        <>
          {t('對內攻擊來源')}
          <Hint text={t('從外面主動連進你主機的可疑位址，例如一直嘗試登入（暴力破解）或被情資列為攻擊者的 IP。')} />
        </>
      }
    >
      <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
        {attackers.map((a) => (
          <li key={a.remoteIp} className="flex flex-wrap items-center gap-2 py-2">
            <VerdictChip verdict={a.worst} t={t} />
            <IpLink ip={a.remoteIp} className="font-mono text-xs" risk={risks[a.remoteIp]} t={t}>
              {a.remoteIp}
            </IpLink>
            <span className="text-xs text-slate-500">
              {t('{hosts} 台主機、{conns} 條連線', { hosts: a.hosts, conns: a.conns })}
              {a.country ? ' · ' : ''}
            </span>
            {a.country ? <CountryFlag code={a.country} t={t} /> : null}
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
