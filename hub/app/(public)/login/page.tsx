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
        <div className="mb-2 flex items-center gap-3">
          <img src="/logo.png" alt="" width={56} height={56} className="h-14 w-14" />
          <div>
            <h1 className="text-lg font-semibold">Security Hub</h1>
            <div className="text-xs text-slate-400">ai-security-monitor</div>
          </div>
        </div>
        <p className="mb-4 text-sm text-slate-500">{t('貼上管理員金鑰（AI_SECURITY_MONITOR_HUB_ADMIN_SECRET）登入')}</p>
        <LoginForm />
      </div>
    </main>
  );
}
