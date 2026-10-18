'use client';

// 清單裡直接編輯 IP 備註：點「加備註」或備註文字就地編輯，Enter 儲存、Esc 取消、清空＝刪除。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

const MAX = 2000;

export function InlineIpNote({ ip, note }: { ip: string; note: string | null }) {
  const { t } = useT();
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(note ?? '');
  const [shown, setShown] = useState(note ?? '');
  const [err, setErr] = useState(false);
  const [pending, start] = useTransition();

  const save = (value: string) =>
    start(async () => {
      setErr(false);
      const r = await apiPost<{ note: { note: string } | null }>('/api/v1/ip-notes', { ip, note: value.trim() });
      if (!r.ok) {
        setErr(true);
        return;
      }
      const next = r.data.note?.note ?? '';
      setShown(next);
      setText(next);
      setEditing(false);
      router.refresh();
    });

  if (!editing) {
    return (
      <button
        type="button"
        onClick={() => setEditing(true)}
        title={shown ? `${shown}\n\n${t('點一下修改')}` : t('寫下這個 IP 是什麼、處理到哪裡（只有管理員看得到）')}
        className={shown ? 'line-clamp-2 text-left hover:underline' : 'text-slate-400 hover:text-teal-700 hover:underline'}
      >
        {shown ? `📝 ${shown}` : t('加備註')}
      </button>
    );
  }
  return (
    <div className="flex min-w-[12rem] flex-col gap-1">
      <input
        autoFocus
        value={text}
        maxLength={MAX}
        disabled={pending}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') save(text);
          if (e.key === 'Escape') {
            setText(shown);
            setEditing(false);
          }
        }}
        placeholder={t('例：同事的電腦、公司 VPN 出口')}
        className="w-full rounded border border-slate-300 bg-white px-1.5 py-0.5 text-xs dark:border-slate-700 dark:bg-slate-950"
      />
      <div className="flex items-center gap-1">
        <button type="button" disabled={pending} onClick={() => save(text)} className="rounded bg-teal-600 px-1.5 py-0.5 text-[11px] text-white disabled:opacity-50">
          {t('儲存')}
        </button>
        <button
          type="button"
          disabled={pending}
          onClick={() => {
            setText(shown);
            setEditing(false);
          }}
          className="rounded border border-slate-300 px-1.5 py-0.5 text-[11px] dark:border-slate-700"
        >
          {t('取消')}
        </button>
        {shown ? (
          <button type="button" disabled={pending} onClick={() => save('')} className="px-1 text-[11px] text-red-600 hover:underline">
            {t('刪除')}
          </button>
        ) : null}
        {err ? <span className="text-[11px] text-red-600">{t('儲存失敗')}</span> : null}
      </div>
    </div>
  );
}
