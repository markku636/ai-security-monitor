import { desc } from 'drizzle-orm';
import { AiConsole } from '@/components/ai/AiConsole';
import { Card } from '@/components/ui/Card';
import { aiAnalyses } from '@/drizzle/schema';
import { PROVIDERS, resolveBin } from '@/lib/ai/run';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { since } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import { listAgents } from '@/lib/queries/agents';
import { strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

export default async function AiPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const scope = ['fleet', 'agent', 'traffic', 'events'].includes(strParam(sp, 'scope', 20) ?? '') ? (strParam(sp, 'scope', 20) as string) : 'fleet';
  const [agents, recent] = await Promise.all([
    listAgents(),
    getDb().select().from(aiAnalyses).orderBy(desc(aiAnalyses.createdAt)).limit(20),
  ]);
  const providers = PROVIDERS.map((p) => ({ id: p, available: !!resolveBin(p) }));
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('AI 分析')}</h1>
        <p className="text-sm text-slate-500">
          {t('在 hub 主機上用 Claude Code 或 Codex 分析整個車隊；AI 透過唯讀的 hub 工具查資料，引用情資時會附來源，不會改動任何設定。')}
        </p>
      </header>
      <AiConsole
        providers={providers}
        agents={agents.map((a) => ({ id: a.id, hostname: a.hostname }))}
        initialScope={scope}
        initialAgent={strParam(sp, 'agent_id', 64)}
      />
      {recent.length ? (
        <Card title={t('最近的分析')}>
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {recent.map((r) => (
              <li key={r.id} className="py-2">
                <details>
                  <summary className="cursor-pointer">
                    <span className="font-medium">{r.prompt.split('\n')[0].slice(0, 80)}</span>{' '}
                    <span className="text-xs text-slate-500">
                      {r.provider} · {r.status} · {t('{n} 次工具呼叫', { n: r.toolsCalled })} · {since(r.createdAt, t)}
                    </span>
                  </summary>
                  {r.resultText ? <div className="mt-2 whitespace-pre-wrap text-sm">{r.resultText}</div> : null}
                  {r.error ? <pre className="mt-2 whitespace-pre-wrap text-xs text-red-700 dark:text-red-400">{r.error}</pre> : null}
                </details>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}
