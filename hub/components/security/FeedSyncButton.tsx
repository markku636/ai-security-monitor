'use client';

// 「立即同步情資」：hub 先抓最新清單，再叫所有主機下次心跳就更新。
// `only` 給了就只更新這幾個來源（每一列的「立即更新」、每一區的「這一區全部更新」）；`compact` 是表格裡的小按鈕。
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useT } from '@/lib/i18n/client';

interface Outcome {
  feed_id: string;
  status: 'updated' | 'not_modified' | 'fresh' | 'error';
  detail?: string;
}

export function FeedSyncButton({ only, label, compact = false }: { only?: string[]; label?: string; compact?: boolean } = {}) {
  const { t } = useT();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [errors, setErrors] = useState<Outcome[]>([]);

  async function run() {
    setBusy(true);
    setMsg(null);
    setErrors([]);
    try {
      const res = await fetch('/api/v1/admin/feeds/sync', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-asa-request': '1' },
        body: JSON.stringify({ force: true, refresh_agents: true, ...(only ? { only } : {}) }),
      });
      const j = (await res.json().catch(() => ({}))) as { outcomes?: Outcome[]; error?: string };
      if (!res.ok || !j.outcomes) {
        setMsg(t('同步失敗：{error}', { error: j.error ?? String(res.status) }));
        return;
      }
      const mine = only ? j.outcomes.filter((o) => only.includes(o.feed_id)) : j.outcomes;
      const n = (s: Outcome['status']) => mine.filter((o) => o.status === s).length;
      if (compact) {
        setMsg(n('error') ? t('失敗') : n('updated') ? t('已更新') : t('沒有新資料'));
      } else {
        setMsg(
          t('完成：{updated} 個有新資料、{same} 個沒變、{bad} 個失敗；主機會在下次心跳（約 1 分鐘內）更新。', {
            updated: n('updated'),
            same: n('not_modified') + n('fresh'),
            bad: n('error'),
          }),
        );
      }
      setErrors(mine.filter((o) => o.status === 'error'));
      router.refresh();
    } catch (e) {
      setMsg(t('同步失敗：{error}', { error: e instanceof Error ? e.message : String(e) }));
    } finally {
      setBusy(false);
    }
  }

  if (compact) {
    return (
      <span className="inline-flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          onClick={run}
          disabled={busy}
          title={t('現在就向廠商下載這份清單（不管更新間隔），並叫所有主機下次心跳時改用新的。')}
          className="whitespace-nowrap rounded-md border border-teal-600 px-2 py-0.5 text-xs font-normal text-teal-700 hover:bg-teal-50 disabled:opacity-60 dark:text-teal-300 dark:hover:bg-teal-950"
        >
          {busy ? t('更新中…') : (label ?? t('立即更新'))}
        </button>
        {msg ? (
          <span className={`text-xs font-normal ${errors.length ? 'text-red-600' : 'text-slate-500'}`} title={errors.map((o) => o.detail ?? '').join('\n') || undefined}>
            {msg}
          </span>
        ) : null}
      </span>
    );
  }

  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className="rounded-md bg-teal-700 px-3 py-1.5 text-sm text-white hover:bg-teal-800 disabled:opacity-60"
      >
        {busy ? t('同步中…（最多約 1 分鐘）') : (label ?? t('立即同步情資'))}
      </button>
      {msg ? <p className="text-sm text-slate-600 dark:text-slate-300">{msg}</p> : null}
      {errors.length ? (
        <ul className="text-xs text-red-700 dark:text-red-400">
          {errors.map((o) => (
            <li key={o.feed_id}>
              {o.feed_id}：{o.detail ?? 'error'}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
