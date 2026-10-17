import { ConnectionsView } from '@/components/security/ConnectionsView';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import { strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export default async function ConnectionsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const params = await searchParams;
  const agentId = strParam(params, 'agent_id', 64);
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
      <ConnectionsView base="/connections" params={params} />
    </div>
  );
}
