import Link from 'next/link';
import { AttackersCard, IntelFeedsCard, RiskyConnectionsCard, ScoreCard, WorstHostsCard } from '@/components/overview/Cards';
import { Badge } from '@/components/ui/Badge';
import { Card, Stat } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { SevCountsRow } from '@/components/ui/Severity';
import { getViewer } from '@/lib/auth/require';
import { pingDb, type DbHealth } from '@/lib/db';
import { env, isOpenMode } from '@/lib/env';
import type { TFn } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import { cachedRisks } from '@/lib/ipintel/service';
import { averageScore, fleetSummary, listAgents } from '@/lib/queries/agents';
import { inboundAttackers, listConnections } from '@/lib/queries/connections';
import { topIntelFeeds } from '@/lib/queries/intel';
import { PerfAlertsCard } from '@/components/metrics/MetricsViews';
import { fmtBytes } from '@/lib/format';
import { perfAlerts, trafficSummary } from '@/lib/queries/metrics';

export const dynamic = 'force-dynamic';

function DbBadge({ t, db }: { t: TFn; db: DbHealth }) {
  if (db.status === 'ok') return <Badge tone="ok">{t('正常（{ms} ms）', { ms: db.latencyMs ?? 0 })}</Badge>;
  if (db.status === 'not_configured') return <Badge tone="warn">{t('未設定 ASA_HUB_DATABASE_URL')}</Badge>;
  return <Badge tone="bad">{t('無法連線')}</Badge>;
}

function HubFooter({ t, db }: { t: TFn; db: DbHealth }) {
  const e = env();
  return (
    <div className="flex flex-wrap gap-4 text-xs text-slate-500">
      <span className="inline-flex items-center gap-2">
        {t('資料庫')} <DbBadge t={t} db={db} />
      </span>
      <span className="inline-flex items-center gap-2">
        {t('存取模式')}{' '}
        {isOpenMode() ? <Badge tone="warn">{t('開放模式（僅本機）')}</Badge> : <Badge tone="ok">{t('需要金鑰')}</Badge>}
      </span>
      <span>
        {e.version} · {e.edition === 'server' ? t('伺服器版') : t('單機版')}
      </span>
    </div>
  );
}

function NoAgents({ t }: { t: TFn }) {
  return (
    <EmptyState title={t('還沒有任何主機回報')}>
      {t('在要保護的電腦上安裝 ai-security-monitor，然後執行：')}
      <code className="mt-2 block rounded bg-slate-100 px-2 py-1 font-mono text-xs dark:bg-slate-800">
        ai-security-monitor enroll https://&lt;hub&gt; --key &lt;client key&gt;
      </code>
    </EmptyState>
  );
}

async function FleetView({ t, isAdmin }: { t: TFn; isAdmin: boolean }) {
  const [fleet, list, feeds, risky, attackers, traffic, alerts] = await Promise.all([
    fleetSummary(),
    listAgents(),
    topIntelFeeds(7, 8),
    isAdmin ? listConnections({ verdict: ['dangerous', 'suspicious'], limit: 100, offset: 0 }) : null,
    isAdmin ? inboundAttackers(5) : [],
    trafficSummary(),
    perfAlerts(),
  ]);
  if (!fleet.agents.total) return <NoAgents t={t} />;
  const risks = isAdmin ? await cachedRisks([...(risky?.items ?? []).map((c) => c.remoteIp), ...attackers.map((a) => a.remoteIp)]) : {};
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-3">
        <ScoreCard t={t} score={averageScore(list)} />
        <div className="grid gap-4">
          <Stat label={t('主機')} value={fleet.agents.total} hint={t('線上 {online}、延遲 {stale}、離線 {offline}', fleet.agents)} />
          <Stat
            label={t('危險連線')}
            value={<span className={fleet.connections.dangerous ? 'text-verdict-dangerous' : ''}>{fleet.connections.dangerous}</span>}
            hint={t('另有 {n} 條可疑', { n: fleet.connections.suspicious })}
          />
          {traffic.reporting ? (
            <Stat
              label={t('24 小時流量（所有主機）')}
              value={
                <span className="text-lg">
                  ↓ {fmtBytes(traffic.rx24h)} · ↑ {fmtBytes(traffic.tx24h)}
                </span>
              }
              hint={t('{n} 台主機回報流量，{p} 台開啟效能蒐集', { n: traffic.hosts24h, p: traffic.perfEnabled })}
            />
          ) : null}
        </div>
      </div>
      <Card title={t('待處理問題')}>
        <SevCountsRow counts={fleet.severities} t={t} />
        {isAdmin ? (
          <Link href="/findings" className="mt-3 inline-block text-sm text-teal-700 hover:underline dark:text-teal-400">
            {t('查看全部待處理問題 →')}
          </Link>
        ) : null}
      </Card>
      <div className="grid gap-4 xl:grid-cols-2">
        {risky ? <RiskyConnectionsCard t={t} risky={risky} risks={risks} /> : null}
        <IntelFeedsCard t={t} feeds={feeds} />
        {attackers.length ? <AttackersCard t={t} attackers={attackers} risks={risks} /> : null}
        <WorstHostsCard t={t} agents={list} linkable={isAdmin} />
        {traffic.perfEnabled || alerts.length ? <PerfAlertsCard t={t} alerts={alerts} perfHosts={traffic.perfEnabled} linkable={isAdmin} /> : null}
      </div>
    </>
  );
}

export default async function Overview() {
  const { t } = await getT();
  const viewer = await getViewer();
  const db = await pingDb();
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">{t('總覽')}</h1>
        <p className="text-sm text-slate-500">{t('所有端點的連線判定、威脅情資命中與弱點，集中在這裡。')}</p>
      </header>
      {db.status === 'ok' ? <FleetView t={t} isAdmin={viewer.role === 'admin'} /> : null}
      <HubFooter t={t} db={db} />
    </div>
  );
}
