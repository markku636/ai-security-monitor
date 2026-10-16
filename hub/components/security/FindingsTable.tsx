'use client';

// 發現表：勾選後批次確認／暫停／重新開啟（寫入有稽核）；展開看細節、建議與情資來源。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiPost } from '@/lib/api-client';
import { since } from '@/lib/format';
import { useT } from '@/lib/i18n/client';
import { SourceBadge, sevText, statusText } from './Verdict';

export interface FindingView {
  agentId: string;
  findingId: string;
  hostname: string;
  scanner: string;
  rule: string;
  severity: string;
  title: string;
  detail: string;
  recommendation: string;
  status: string;
  indicator: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  ackedBy: string | null;
  suppressedUntil: string | null;
  allowlistedBy: string | null;
  tags: string[];
  intelHits: { feed_id: string; name: string; vendor: string; confidence: number; license: string; source_url: string; fetched_at?: string; matched?: string }[];
  proposed: { kind: string; params: Record<string, unknown>; description: string; destructive?: boolean }[];
}

/** hub 能派送給 agent 的動作種類。 */
const REMOTE_KINDS = ['block_ip', 'unblock_ip', 'close_port'];

function ProposeButton({ f, a }: { f: FindingView; a: FindingView['proposed'][number] }) {
  const { t } = useT();
  const [state, setState] = useState<string | null>(null);
  const [busy, start] = useTransition();
  const submit = () =>
    start(async () => {
      const res = await apiPost<{ error?: string }>('/api/v1/actions', {
        agent_id: f.agentId,
        kind: a.kind,
        params: a.params,
        finding_id: f.findingId,
        reason: f.title,
      });
      setState(
        res.ok
          ? t('已送審，到「動作」頁核准後才會執行')
          : res.data.error === 'duplicate'
            ? t('已經有同樣的動作在審核或執行中')
            : t('送審失敗：{error}', { error: res.data.error ?? res.status }),
      );
    });
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button
        type="button"
        disabled={busy || state !== null}
        onClick={submit}
        className="rounded-md border border-teal-600 px-2 py-0.5 text-teal-700 hover:bg-teal-50 disabled:opacity-50 dark:text-teal-300 dark:hover:bg-teal-950"
      >
        {t('送審：{action}', { action: a.description })}
      </button>
      {state ? <span role="status">{state}</span> : null}
    </span>
  );
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

const key = (f: FindingView) => `${f.agentId}\u0000${f.findingId}`;

export function FindingsTable({ rows, canWrite, showHost = true }: { rows: FindingView[]; canWrite: boolean; showHost?: boolean }) {
  const { t } = useT();
  const router = useRouter();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [msg, setMsg] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const all = rows.length > 0 && rows.every((r) => sel.has(key(r)));

  const run = (action: 'ack' | 'suppress' | 'reopen') => {
    const keys = rows.filter((r) => sel.has(key(r))).map((r) => ({ agent_id: r.agentId, finding_id: r.findingId }));
    if (!keys.length) return;
    start(async () => {
      const res = await apiPost<{ changed?: number; error?: string }>('/api/v1/findings', { action, keys, days: 30 });
      if (res.ok) {
        setMsg(t('已更新 {n} 筆', { n: res.data.changed ?? 0 }));
        setSel(new Set());
        router.refresh();
      } else {
        setMsg(t('更新失敗（HTTP {status}）', { status: res.status }));
      }
    });
  };

  return (
    <div className="space-y-2">
      {canWrite ? (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-slate-500">{t('已選 {n} 筆', { n: sel.size })}</span>
          <button type="button" disabled={!sel.size || pending} onClick={() => run('ack')} className="rounded-md border border-slate-300 px-2 py-1 disabled:opacity-40 dark:border-slate-700">
            {t('標記已確認')}
          </button>
          <button type="button" disabled={!sel.size || pending} onClick={() => run('suppress')} className="rounded-md border border-slate-300 px-2 py-1 disabled:opacity-40 dark:border-slate-700">
            {t('暫停 30 天')}
          </button>
          <button type="button" disabled={!sel.size || pending} onClick={() => run('reopen')} className="rounded-md border border-slate-300 px-2 py-1 disabled:opacity-40 dark:border-slate-700">
            {t('重新開啟')}
          </button>
          {msg ? <span className="text-slate-500" role="status">{msg}</span> : null}
        </div>
      ) : null}
      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800">
            <tr>
              {canWrite ? (
                <th className="w-8 px-3 py-2">
                  <input
                    type="checkbox"
                    aria-label={t('全選')}
                    checked={all}
                    onChange={() => setSel(all ? new Set() : new Set(rows.map(key)))}
                  />
                </th>
              ) : null}
              <th className="px-3 py-2">{t('嚴重度')}</th>
              <th className="px-3 py-2">{t('發現')}</th>
              {showHost ? <th className="px-3 py-2">{t('主機')}</th> : null}
              <th className="px-3 py-2">{t('狀態')}</th>
              <th className="px-3 py-2">{t('最後出現')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={key(f)} className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
                {canWrite ? (
                  <td className="px-3 py-2">
                    <input
                      type="checkbox"
                      aria-label={f.title}
                      checked={sel.has(key(f))}
                      onChange={() => {
                        const n = new Set(sel);
                        if (n.has(key(f))) n.delete(key(f));
                        else n.add(key(f));
                        setSel(n);
                      }}
                    />
                  </td>
                ) : null}
                <td className="px-3 py-2 whitespace-nowrap">
                  <span className="inline-flex items-center gap-1.5">
                    <span className={`h-2.5 w-2.5 rounded-full ${SEV_DOT[f.severity] ?? 'bg-sev-info'}`} aria-hidden />
                    {sevText(t, f.severity)}
                  </span>
                </td>
                <td className="px-3 py-2">
                  <details>
                    <summary className="cursor-pointer">
                      <span className="font-medium">{f.title}</span>
                      <span className="ml-2 font-mono text-xs text-slate-500">{f.rule}</span>
                    </summary>
                    <div className="mt-2 space-y-2 text-xs text-slate-600 dark:text-slate-300">
                      <p className="whitespace-pre-wrap">{f.detail}</p>
                      {f.recommendation ? (
                        <p>
                          <span className="font-semibold">{t('建議：')}</span>
                          {f.recommendation}
                        </p>
                      ) : null}
                      {f.intelHits.length ? (
                        <div className="flex flex-wrap items-center gap-1">
                          <span className="font-semibold">{t('情資來源：')}</span>
                          {f.intelHits.map((h, i) => (
                            <SourceBadge key={i} r={{ type: 'intel_hit', ...h }} t={t} />
                          ))}
                        </div>
                      ) : null}
                      {canWrite && f.proposed.some((a) => REMOTE_KINDS.includes(a.kind)) ? (
                        <div className="flex flex-wrap items-center gap-2">
                          {f.proposed
                            .filter((a) => REMOTE_KINDS.includes(a.kind))
                            .map((a, i) => (
                              <ProposeButton key={i} f={f} a={a} />
                            ))}
                        </div>
                      ) : null}
                      <p className="text-slate-500">
                        {t('首次出現 {a}', { a: since(f.firstSeenAt, t) })}
                        {f.ackedBy ? ` · ${t('處理者 {who}', { who: f.ackedBy })}` : ''}
                        {f.allowlistedBy ? ` · ${t('agent 白名單 {id}', { id: f.allowlistedBy })}` : ''}
                      </p>
                    </div>
                  </details>
                </td>
                {showHost ? (
                  <td className="px-3 py-2 whitespace-nowrap">
                    <Link href={`/agents/${encodeURIComponent(f.agentId)}?tab=findings`} className="hover:underline">
                      {f.hostname}
                    </Link>
                  </td>
                ) : null}
                <td className="px-3 py-2 whitespace-nowrap">{statusText(t, f.status)}</td>
                <td className="px-3 py-2 whitespace-nowrap text-slate-500">{since(f.lastSeenAt, t)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
