import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import { LoginForm } from './LoginForm';

export const dynamic = 'force-dynamic';

export default async function LoginPage() {
  const viewer = await getViewer();
  if (viewer.role === 'admin') redirect('/');
  const { t } = await getT();
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h1 className="text-lg font-semibold">Security Hub</h1>
        <p className="mb-4 text-sm text-slate-500">{t('貼上管理員金鑰（ASA_HUB_ADMIN_SECRET）登入')}</p>
        <LoginForm />
      </div>
    </main>
  );
}
