import { ConnectionsView } from '@/components/security/ConnectionsView';
import { RiskyIpRanking } from '@/components/security/RiskyIpRanking';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import { riskyIpRanking } from '@/lib/queries/connections';
import { clampInt, strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

/** 保留目前的篩選條件，只換排名顯示幾名。 */
function rankHref(params: Record<string, string | string[] | undefined>, rank: number | undefined): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (k === 'rank' || v == null) continue;
    for (const one of Array.isArray(v) ? v : [v]) q.append(k, one);
  }
  if (rank) q.set('rank', String(rank));
  const s = q.toString();
  return `/connections${s ? `?${s}` : ''}`;
}

export default async function ConnectionsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const params = await searchParams;
  const agentId = strParam(params, 'agent_id', 64);
  const rank = clampInt(params, 'rank', 10, 5, 50);
  const ranking = await riskyIpRanking(rank, agentId);
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">{t('連線')}</h1>
          <p className="text-sm text-slate-500">
            {t('每台主機最新快照裡的連線：對外、對內與監聽，依威脅情資與異常行為判定安全、可疑或危險。點 IP 可看詳細分析。')}
          </p>
        </div>
        <a
          href={`/ai?scope=connections${agentId ? `&agent_id=${encodeURIComponent(agentId)}` : ''}`}
          className="rounded-md border border-teal-600 px-2.5 py-1 text-xs text-teal-700 hover:bg-teal-50 dark:text-teal-300 dark:hover:bg-teal-950"
        >
          {t('請 AI 分析可疑連線')}
        </a>
      </header>
      <RiskyIpRanking
        t={t}
        ranking={ranking}
        moreHref={rank < 50 && ranking.total > rank ? rankHref(params, 50) : undefined}
        lessHref={rank > 10 ? rankHref(params, undefined) : undefined}
      />
      <ConnectionsView base="/connections" params={params} />
    </div>
  );
}
