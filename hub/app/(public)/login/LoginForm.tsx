'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

export function LoginForm({ keycloakEnabled, keycloakOnly }: { keycloakEnabled: boolean; keycloakOnly: boolean }) {
  const { t } = useT();
  const router = useRouter();
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const r = await apiPost<{ error?: string }>('/api/auth/login', { key });
    setBusy(false);
    if (r.ok) {
      router.push('/');
      router.refresh();
      return;
    }
    setMsg(
      r.status === 429 ? t('嘗試太多次，請一分鐘後再試') : r.status === 401 ? t('金鑰不正確') : t('登入失敗（{status}）', { status: r.status }),
    );
  }

  return (
    <div className="space-y-4">
      {keycloakEnabled ? (
        <a
          href="/api/auth/keycloak/login"
          className="block w-full rounded-md bg-teal-700 px-3 py-2 text-center text-sm font-medium text-white hover:bg-teal-800"
        >
          {t('使用 Keycloak 登入')}
        </a>
      ) : null}
      {keycloakEnabled && !keycloakOnly ? (
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
          {t('或使用管理員金鑰')}
          <span className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
        </div>
      ) : null}
      {!keycloakEnabled || !keycloakOnly ? (
        <form onSubmit={submit} className="space-y-3">
          <label className="block text-sm">
            <span className="mb-1 block text-slate-600 dark:text-slate-300">{t('管理員金鑰')}</span>
            <input
              type="password"
              autoComplete="current-password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-teal-600 focus:ring-2 focus:ring-teal-600/20 dark:border-slate-700 dark:bg-slate-950"
              required
            />
          </label>
          {msg ? (
            <p role="alert" className="text-sm text-red-600">
              {msg}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={busy || !key}
            className="w-full rounded-md bg-teal-700 px-3 py-2 text-sm font-medium text-white hover:bg-teal-800 disabled:opacity-50"
          >
            {busy ? t('登入中…') : t('登入')}
          </button>
        </form>
      ) : null}
    </div>
  );
}
