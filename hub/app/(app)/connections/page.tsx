import { ConnectionsView } from '@/components/security/ConnectionsView';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';

export const dynamic = 'force-dynamic';

export default async function ConnectionsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const params = await searchParams;
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('連線')}</h1>
        <p className="text-sm text-slate-500">
          {t('每台主機最新快照裡的連線：對外、對內與監聽，依威脅情資與異常行為判定安全、可疑或危險。')}
        </p>
      </header>
      <ConnectionsView base="/connections" params={params} />
    </div>
  );
}
