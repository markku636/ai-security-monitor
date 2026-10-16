import { FindingsView } from '@/components/security/FindingsView';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';

export const dynamic = 'force-dynamic';

export default async function FindingsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const params = await searchParams;
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('發現')}</h1>
        <p className="text-sm text-slate-500">{t('所有主機回報的問題。確認或暫停後不會再計入未處理數；問題消失時會自動標為已解決。')}</p>
      </header>
      <FindingsView base="/findings" params={params} />
    </div>
  );
}
