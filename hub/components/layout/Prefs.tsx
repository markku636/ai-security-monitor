'use client';

import { useRouter } from 'next/navigation';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

export function LangSwitch() {
  const { lang, t } = useT();
  const router = useRouter();
  const next = lang === 'en' ? 'zh-TW' : 'en';
  return (
    <button
      type="button"
      className="rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 hover:text-white"
      onClick={async () => {
        await apiPost('/api/prefs', { lang: next });
        router.refresh();
      }}
      aria-label={t('切換語言')}
    >
      {lang === 'en' ? '中文' : 'English'}
    </button>
  );
}

export function ThemeToggle() {
  const { t } = useT();
  const router = useRouter();
  return (
    <button
      type="button"
      className="rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 hover:text-white"
      onClick={async () => {
        const dark = document.documentElement.classList.contains('dark');
        await apiPost('/api/prefs', { theme: dark ? 'light' : 'dark' });
        router.refresh();
      }}
    >
      {t('深色／淺色')}
    </button>
  );
}

export function LogoutButton() {
  const { t } = useT();
  const router = useRouter();
  return (
    <button
      type="button"
      className="rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 hover:text-white"
      onClick={async () => {
        await apiPost('/api/auth/logout', {});
        router.push('/login');
        router.refresh();
      }}
    >
      {t('登出')}
    </button>
  );
}
