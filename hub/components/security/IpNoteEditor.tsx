'use client';

// IP 分析頁的人工備註：寫下這個 IP 是什麼、處理到哪裡，排名與連線表會跟著顯示。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiPost } from '@/lib/api-client';
import { since } from '@/lib/format';
import { useT } from '@/lib/i18n/client';

const MAX = 2000;

export function IpNoteEditor({
  ip,
  initial,
  updatedAt,
  updatedBy,
}: {
  ip: string;
  initial: string;
  updatedAt?: string | null;
  updatedBy?: string | null;
}) {
  const { t } = useT();
  const router = useRouter();
  const [text, setText] = useState(initial);
  const [saved, setSaved] = useState(initial);
  const [msg, setMsg] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const dirty = text.trim() !== saved.trim();

  const save = (value: string) =>
    start(async () => {
      setMsg(null);
      const r = await apiPost<{ note: { note: string } | null }>('/api/v1/ip-notes', { ip, note: value });
      if (!r.ok) {
        setMsg(t('儲存失敗（{status}）', { status: r.status }));
        return;
      }
      const next = r.data.note?.note ?? '';
      setText(next);
      setSaved(next);
      setMsg(next ? t('已儲存') : t('已刪除備註'));
      router.refresh();
    });

  return (
    <div className="space-y-2">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value.slice(0, MAX))}
        rows={3}
        placeholder={t('例如：公司 VPN 出口，已確認安全／某同事的測試機，持續觀察')}
        className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-950"
      />
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <button
          type="button"
          disabled={pending || !dirty}
          onClick={() => save(text)}
          className="rounded-md bg-teal-600 px-3 py-1.5 font-medium text-white hover:bg-teal-700 disabled:opacity-50"
        >
          {pending ? t('儲存中…') : t('儲存備註')}
        </button>
        {saved ? (
          <button
            type="button"
            disabled={pending}
            onClick={() => save('')}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-slate-600 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            {t('刪除備註')}
          </button>
        ) : null}
        <span className="text-slate-500">
          {msg ??
            (updatedAt && saved
              ? t('最後修改：{when}（{who}）', { when: since(updatedAt, t), who: updatedBy ?? '—' })
              : t('只有管理員看得到；會記在稽核紀錄。'))}
        </span>
        <span className="ml-auto tabular-nums text-slate-400">
          {text.length}/{MAX}
        </span>
      </div>
    </div>
  );
}
