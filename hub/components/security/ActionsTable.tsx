'use client';

// 遠端動作審核表：核准／拒絕／取消；破壞性動作核准前要輸入主機名稱。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiPost } from '@/lib/api-client';
import { since } from '@/lib/format';
import { useT } from '@/lib/i18n/client';
import { actionStatusText, describeAction } from './actionLabels';

export interface ActionView {
  id: string;
  agentId: string;
  hostname: string;
  agentAccepts: boolean;
  kind: string;
  params: Record<string, unknown>;
  reason: string;
  status: string;
  destructive: boolean;
  proposedBy: string;
  createdAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  completedAt: string | null;
  resultOk: boolean | null;
  resultOutput: string | null;
}

const STATUS_TONE: Record<string, string> = {
  pending: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
  approved: 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300',
  dispatched: 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300',
  succeeded: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  failed: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
};

function Row({ a }: { a: ActionView }) {
  const { t } = useT();
  const router = useRouter();
  const [busy, start] = useTransition();
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const decide = (decision: 'approve' | 'reject' | 'cancel') =>
    start(async () => {
      const res = await apiPost<{ error?: string }>(`/api/v1/actions/${encodeURIComponent(a.id)}`, {
        decision,
        confirm_hostname: confirm || undefined,
      });
      if (res.ok) {
        setErr(null);
        router.refresh();
      } else {
        const e = res.data.error ?? String(res.status);
        setErr(
          e === 'confirm_hostname'
            ? t('主機名稱不符')
            : e === 'agent_does_not_accept_actions'
              ? t('這台主機沒有開啟遠端動作（ai-security-monitor enroll --accept-remote-actions）')
              : t('操作失敗：{error}', { error: e }),
        );
      }
    });
  const btn = 'rounded-md border px-2 py-1 text-xs disabled:opacity-40';
  return (
    <tr className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
      <td className="px-3 py-2 whitespace-nowrap">
        <span className={`rounded px-1.5 py-0.5 text-xs ${STATUS_TONE[a.status] ?? 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'}`}>
          {actionStatusText(t, a.status)}
        </span>
        {a.destructive ? <div className="mt-1 text-xs text-red-700 dark:text-red-400">{t('破壞性')}</div> : null}
      </td>
      <td className="px-3 py-2">
        <div className="font-medium">{describeAction(t, a.kind, a.params)}</div>
        {a.reason ? <div className="text-xs text-slate-500">{a.reason}</div> : null}
        {a.resultOutput ? (
          <pre className="mt-1 max-w-xl whitespace-pre-wrap break-all rounded bg-slate-50 p-1.5 text-xs dark:bg-slate-800">{a.resultOutput}</pre>
        ) : null}
      </td>
      <td className="px-3 py-2 whitespace-nowrap">
        {a.hostname}
        {!a.agentAccepts ? <div className="text-xs text-amber-700 dark:text-amber-400">{t('未開啟遠端動作')}</div> : null}
      </td>
      <td className="px-3 py-2 text-xs text-slate-500">
        <div>{t('{who} 提出，{when}', { who: a.proposedBy, when: since(a.createdAt, t) })}</div>
        {a.reviewedBy ? <div>{t('{who} 審核', { who: a.reviewedBy })}</div> : null}
      </td>
      <td className="px-3 py-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {a.status === 'pending' ? (
            <>
              {a.destructive ? (
                <input
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder={t('輸入 {host} 確認', { host: a.hostname })}
                  aria-label={t('輸入主機名稱確認')}
                  className="w-40 rounded border border-slate-300 bg-white px-1.5 py-1 text-xs dark:border-slate-700 dark:bg-slate-900"
                />
              ) : null}
              <button
                type="button"
                disabled={busy || (a.destructive && confirm !== a.hostname)}
                onClick={() => decide('approve')}
                className={`${btn} border-teal-600 bg-teal-600 text-white`}
              >
                {t('核准')}
              </button>
              <button type="button" disabled={busy} onClick={() => decide('reject')} className={`${btn} border-slate-300 dark:border-slate-700`}>
                {t('拒絕')}
              </button>
            </>
          ) : null}
          {a.status === 'approved' || a.status === 'dispatched' ? (
            <button type="button" disabled={busy} onClick={() => decide('cancel')} className={`${btn} border-slate-300 dark:border-slate-700`}>
              {t('取消')}
            </button>
          ) : null}
        </div>
        {err ? (
          <div role="alert" className="mt-1 text-xs text-red-700 dark:text-red-400">
            {err}
          </div>
        ) : null}
      </td>
    </tr>
  );
}

export function ActionsTable({ rows }: { rows: ActionView[] }) {
  const { t } = useT();
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800">
          <tr>
            <th className="px-3 py-2">{t('狀態')}</th>
            <th className="px-3 py-2">{t('動作')}</th>
            <th className="px-3 py-2">{t('主機')}</th>
            <th className="px-3 py-2">{t('來源')}</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <Row key={a.id} a={a} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
