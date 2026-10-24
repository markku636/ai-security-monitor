// 掃描工作清單（沒有 hook：server 元件直接用；取消按鈕是 client 元件）。
import Link from 'next/link';
import { Badge } from '@/components/ui/Badge';
import type { TFn } from '@/lib/i18n/core';
import type { JobView } from '@/lib/webscan/jobs';
import { durationText, errorText, jobStatusLabel, kindLabel, profileLabel } from './labels';
import { CancelJobButton } from './TargetActions';

export function JobsTable({ t, jobs, targets }: { t: TFn; jobs: JobView[]; targets?: Map<string, string> }) {
  if (!jobs.length) return <p className="text-sm text-slate-500">{t('還沒有掃描紀錄。')}</p>;
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap [&_th]:px-3 [&_th]:py-2">
          <tr>
            <th>{t('建立時間')}</th>
            {targets ? <th>{t('目標')}</th> : null}
            <th>{t('種類')}</th>
            <th>{t('狀態')}</th>
            <th>{t('掃描器')}</th>
            <th>{t('花費')}</th>
            <th>{t('結果')}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {jobs.map((j) => {
            const st = jobStatusLabel(t, j.status);
            const progress = j.progress as { step?: string | null; message?: string | null; warnings?: string[] };
            return (
              <tr key={j.id} className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800 [&_td]:px-3 [&_td]:py-2">
                <td className="whitespace-nowrap text-xs text-slate-500">{j.createdAt.slice(0, 16).replace('T', ' ')}</td>
                {targets ? (
                  <td className="max-w-xs truncate font-mono text-xs">
                    <Link className="text-teal-700 hover:underline dark:text-teal-400" href={`/web/${j.targetId}`}>
                      {targets.get(j.targetId) ?? j.targetId}
                    </Link>
                  </td>
                ) : null}
                <td className="whitespace-nowrap">{j.kind === 'verify' ? kindLabel(t, j.kind) : profileLabel(t, j.profile)}</td>
                <td className="whitespace-nowrap">
                  <Badge tone={st.tone}>{st.text}</Badge>
                  {j.status === 'running' && progress.step ? <span className="ml-1 text-xs text-slate-500">{progress.step}</span> : null}
                </td>
                <td className="text-xs text-slate-500">{j.scanners.join(', ') || '—'}</td>
                <td className="whitespace-nowrap text-xs text-slate-500">{durationText(j.claimedAt, j.finishedAt)}</td>
                <td className="text-xs">
                  {j.summary ? t('新 {n}・未處理 {o}・已解決 {r}', { n: j.summary.new, o: j.summary.open, r: j.summary.resolved }) : null}
                  {j.error ? <div className="text-red-700 dark:text-red-400">{errorText(t, j.error, 0)}</div> : null}
                </td>
                <td className="whitespace-nowrap text-right">{j.status === 'pending' || j.status === 'running' ? <CancelJobButton jobId={j.id} /> : null}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
