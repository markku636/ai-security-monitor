'use client';

// 情資頁的「情資來源授權」：Hub 是公司／商業用途（預設）還是個人／非商業用途。非商用才鏡像只限非商業用途的來源給主機。
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useT } from '@/lib/i18n/client';

type Usage = 'commercial' | 'noncommercial';

export function IntelUsageSetting({ usage, locked, sources }: { usage: Usage; locked: boolean; sources: string[] }) {
  const { t } = useT();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function choose(next: Usage) {
    if (next === usage || busy) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch('/api/v1/admin/intel-usage', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', 'x-asa-request': '1' },
        body: JSON.stringify({ usage: next }),
      });
      const j = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) {
        setMsg(t('儲存失敗：{error}', { error: j.error ?? String(res.status) }));
        return;
      }
      setMsg(next === 'noncommercial' ? t('已啟用只限非商業用途的來源；按「立即同步」就會下載。') : t('之後只鏡像可以商用的來源。'));
      router.refresh();
    } finally {
      setBusy(false);
    }
  }

  const option = (value: Usage, title: string, text: string) => (
    <label className={`flex cursor-pointer items-start gap-2 rounded-lg border p-3 text-sm ${usage === value ? 'border-teal-500 bg-teal-50 dark:bg-teal-950/30' : 'border-slate-200 dark:border-slate-700'} ${locked ? 'cursor-not-allowed opacity-70' : ''}`}>
      <input type="radio" name="intel-usage" className="mt-1" checked={usage === value} disabled={locked || busy} onChange={() => choose(value)} />
      <span>
        <span className="font-medium">{title}</span>
        <span className="block text-xs text-slate-500">{text}</span>
      </span>
    </label>
  );

  return (
    <div className="space-y-2">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {t('情資來源各有授權：有些只准個人或非營利使用（例如 DShield、URLhaus），公司或營利用途要另外向廠商買授權。選「公司／商業用途」時 Hub 只鏡像可以商用的來源。')}
      </p>
      <div className="flex flex-col gap-2 sm:flex-row">
        {option('commercial', t('公司／商業用途（預設）'), t('只鏡像可以商用的情資來源，大部分來源都可以。'))}
        {option('noncommercial', t('個人／非商業用途'), t('另外鏡像 {n} 個只限非商業用途的來源：{list}', { n: sources.length, list: sources.join('、') }))}
      </div>
      {locked ? <p className="text-xs text-slate-500">{t('由環境變數 AI_SECURITY_MONITOR_HUB_INTEL_USAGE 指定，網頁上不能改。')}</p> : null}
      <p className="text-xs text-slate-500">{t('各台電腦的桌面版第一次打開時也會自己問一次，兩邊分開設定：主機選商用時，就算 Hub 有鏡像也不會用。')}</p>
      {msg ? <p className="text-xs text-teal-700 dark:text-teal-300">{msg}</p> : null}
    </div>
  );
}
