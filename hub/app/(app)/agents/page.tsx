import { Badge } from '@/components/ui/Badge';
import { EmptyState } from '@/components/ui/EmptyState';
import { ScorePill, SevCountsRow } from '@/components/ui/Severity';
import { getT } from '@/lib/i18n/server';
import { listAgents, type AgentStatus } from '@/lib/queries/agents';

export const dynamic = 'force-dynamic';

function since(d: Date | null, t: (zh: string, p?: Record<string, string | number>) => string): string {
  if (!d) return '—';
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (s < 60) return t('{n} 秒前', { n: s });
  if (s < 3600) return t('{n} 分鐘前', { n: Math.round(s / 60) });
  if (s < 86400) return t('{n} 小時前', { n: Math.round(s / 3600) });
  return t('{n} 天前', { n: Math.round(s / 86400) });
}

export default async function AgentsPage() {
  const { t } = await getT();
  const rows = await listAgents();
  const statusBadge = (s: AgentStatus) =>
    s === 'online' ? <Badge tone="ok">{t('線上')}</Badge> : s === 'stale' ? <Badge tone="warn">{t('延遲')}</Badge> : <Badge>{t('離線')}</Badge>;
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('代理程式')}</h1>
        <p className="text-sm text-slate-500">{t('每台安裝 asa 並註冊到這個 Hub 的電腦或伺服器。')}</p>
      </header>
      {rows.length === 0 ? (
        <EmptyState title={t('還沒有任何代理程式回報')}>{t('在要保護的電腦上安裝 asa，然後執行：')}</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs uppercase text-slate-500 dark:border-slate-800">
              <tr>
                <th className="px-3 py-2">{t('主機')}</th>
                <th className="px-3 py-2">{t('狀態')}</th>
                <th className="px-3 py-2">{t('系統')}</th>
                <th className="px-3 py-2">{t('分數')}</th>
                <th className="px-3 py-2">{t('未處理的發現')}</th>
                <th className="px-3 py-2">{t('最後回報')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className="border-b border-slate-100 last:border-0 dark:border-slate-800">
                  <td className="px-3 py-2">
                    <div className="font-medium">{a.hostname}</div>
                    <div className="text-xs text-slate-500">{a.ips.slice(0, 3).join(', ')}</div>
                  </td>
                  <td className="px-3 py-2">
                    {statusBadge(a.status)}
                    {a.partial ? (
                      <span className="ml-1">
                        <Badge tone="info">{t('部分資料')}</Badge>
                      </span>
                    ) : null}
                  </td>
                  <td className="px-3 py-2 text-slate-600 dark:text-slate-300">
                    {[a.osName ?? a.osFamily, a.osVersion].filter(Boolean).join(' ')}
                    <div className="text-xs text-slate-500">asa {a.version}</div>
                  </td>
                  <td className="px-3 py-2">
                    <ScorePill score={a.score?.overall} />
                  </td>
                  <td className="px-3 py-2">
                    <SevCountsRow counts={a.sevCounts} t={t} />
                  </td>
                  <td className="px-3 py-2 text-slate-500">{since(a.lastSeenAt, t)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
