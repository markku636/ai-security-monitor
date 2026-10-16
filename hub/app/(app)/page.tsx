import { Badge } from '@/components/ui/Badge';
import { Card, Stat } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { pingDb } from '@/lib/db';
import { env, isOpenMode } from '@/lib/env';
import { getT } from '@/lib/i18n/server';

export const dynamic = 'force-dynamic';

export default async function Overview() {
  const { t } = await getT();
  const db = await pingDb();
  const e = env();
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">{t('總覽')}</h1>
        <p className="text-sm text-slate-500">{t('所有端點的連線判定、威脅情資命中與弱點，集中在這裡。')}</p>
      </header>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label={t('代理程式')} value="0" hint={t('尚未有端點回報')} />
        <Stat label={t('版本')} value={e.version} hint={e.edition === 'server' ? t('伺服器版') : t('單機版')} />
        <Card title={t('資料庫')}>
          {db.status === 'ok' ? (
            <Badge tone="ok">{t('正常（{ms} ms）', { ms: db.latencyMs ?? 0 })}</Badge>
          ) : db.status === 'not_configured' ? (
            <Badge tone="warn">{t('未設定 ASA_HUB_DATABASE_URL')}</Badge>
          ) : (
            <Badge tone="bad">{t('無法連線')}</Badge>
          )}
        </Card>
        <Card title={t('存取模式')}>
          {isOpenMode() ? <Badge tone="warn">{t('開放模式（僅本機）')}</Badge> : <Badge tone="ok">{t('需要金鑰')}</Badge>}
        </Card>
      </div>

      <EmptyState title={t('還沒有任何代理程式回報')}>
        {t('在要保護的電腦上安裝 asa，然後執行：')}
        <code className="mt-2 block rounded bg-slate-100 px-2 py-1 font-mono text-xs dark:bg-slate-800">
          asa enroll https://&lt;hub&gt; --key &lt;client key&gt;
        </code>
      </EmptyState>
    </div>
  );
}
