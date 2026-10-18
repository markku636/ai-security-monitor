'use client';

// DNS 頁的「黑白名單」：貼網域直接加進 Hub 的黑名單或白名單（全公司，含子網域），顯示目前筆數。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

export function DnsListQuickAdd({ blocked, allowed }: { blocked: number; allowed: number }) {
  const { t } = useT();
  const router = useRouter();
  const [text, setText] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [pending, start] = useTransition();
  const send = (key: 'block_add' | 'allow_add') => {
    const domains = text.split(/[\s,]+/).filter(Boolean);
    if (!domains.length) return;
    setMsg(null);
    start(async () => {
      const r = await apiPost<{ invalid?: string[] }>('/api/v1/admin/dns-protect', { [key]: domains });
      if (!r.ok) {
        setMsg({ ok: false, text: t('失敗（HTTP {n}）', { n: r.status }) });
        return;
      }
      const bad = r.data.invalid ?? [];
      setMsg({
        ok: bad.length === 0,
        text: bad.length ? t('不是合法的網域：{l}', { l: bad.join('、') }) : key === 'block_add' ? t('已加入黑名單') : t('已加入白名單'),
      });
      if (!bad.length) setText('');
      router.refresh();
    });
  };
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-200 bg-white p-3 text-sm shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <span className="flex items-center font-medium">
        {t('黑白名單')}
        <Hint text={t('全公司共用、含子網域。黑名單：防護 DNS 直接擋、每台電腦查到就告警。白名單：防護 DNS 永遠不擋、也不告警（情資誤判、公司內部系統用）。')} />
      </span>
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') send('block_add');
        }}
        placeholder={t('網域或網址，例：bad.example')}
        className="w-64 rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-950"
      />
      <button type="button" disabled={pending || !text.trim()} onClick={() => send('block_add')} className="rounded-md border border-red-600 px-2.5 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50 dark:text-red-300 dark:hover:bg-red-950">
        {t('加入黑名單')}
      </button>
      <button type="button" disabled={pending || !text.trim()} onClick={() => send('allow_add')} className="rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800">
        {t('加入白名單')}
      </button>
      <Link href="/admin?tab=dns" className="text-xs text-slate-500 hover:underline">
        {t('黑名單 {b} 筆、白名單 {a} 筆 →', { b: blocked, a: allowed })}
      </Link>
      {msg ? <span className={`text-xs ${msg.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-600'}`}>{msg.text}</span> : null}
    </div>
  );
}
