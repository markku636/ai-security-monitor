'use client';

// 新增掃描目標：輸入網址（沒寫 http:// 就當 https），Hub 只做 DNS 解析看位址落在哪，不會連過去。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';
import { blockReasonText, errorText } from './labels';

const INPUT = 'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900';
const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';

type Created = { target?: { id: string; url: string }; screen?: { ok: boolean; internal?: boolean; reason?: string }; error?: string };

export function AddTargetForm() {
  const { t } = useT();
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string; id?: string; settings?: boolean } | null>(null);

  const submit = () => {
    setMsg(null);
    start(async () => {
      const r = await apiPost<Created>('/api/v1/admin/webscan/targets', { url: url.trim(), name: name.trim() || undefined });
      if (!r.ok || !r.data.target) {
        setMsg({ ok: false, text: errorText(t, r.data.error, r.status) });
        return;
      }
      const s = r.data.screen;
      const note = !s?.ok
        ? t('已新增，但目前不能掃：{why}', { why: blockReasonText(t, s?.reason ?? '') })
        : s.internal
          ? t('已新增：位址在內網白名單裡，可以直接掃描。')
          : t('已新增：打開目標頁面即可手動執行被動或主動檢查。');
      setMsg({ ok: !!s?.ok, text: note, id: r.data.target.id, settings: s?.reason === 'private_not_allowed' });
      setUrl('');
      setName('');
      router.refresh();
    });
  };

  return (
    <div className="space-y-2">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (url.trim()) submit();
        }}
      >
        <label className="min-w-64 flex-1 text-sm">
          <div className="text-xs text-slate-500">{t('網址')}</div>
          <input className={`${INPUT} w-full font-mono`} value={url} maxLength={2048} onChange={(e) => setUrl(e.target.value)} placeholder="https://shop.example.com" />
        </label>
        <label className="text-sm">
          <div className="text-xs text-slate-500">{t('名稱（選填）')}</div>
          <input className={`${INPUT} w-56 max-w-full`} value={name} maxLength={120} onChange={(e) => setName(e.target.value)} placeholder={t('例：官網、訂單系統')} />
        </label>
        <button type="submit" className={BTN} disabled={pending || !url.trim()}>
          {t('新增目標')}
        </button>
      </form>
      {msg ? (
        <p className={`text-sm ${msg.ok ? 'text-teal-700 dark:text-teal-400' : 'text-amber-700 dark:text-amber-400'}`} role="status">
          {msg.text}
          {msg.id ? (
            <Link className="ml-2 underline" href={`/web/${msg.id}`}>
              {t('打開')}
            </Link>
          ) : null}
          {msg.settings ? (
            <Link className="ml-2 underline" href="/admin?tab=webscan">
              {t('設定內網白名單')}
            </Link>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}
