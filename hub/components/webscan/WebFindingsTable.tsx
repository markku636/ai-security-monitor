'use client';

// 網站掃描的發現：嚴重度、標題（Hub 產生的會翻譯、工具給的原樣）、規則、位置；可勾選後標為已讀、忽略 30 天、重新開啟。
import { useRouter } from 'next/navigation';
import { Fragment, useMemo, useState, useTransition } from 'react';
import { sevLabel } from '@/components/ui/Severity';
import { apiPost } from '@/lib/api-client';
import type { TFn } from '@/lib/i18n/core';
import { useT } from '@/lib/i18n/client';
import type { WebFindingView } from '@/lib/webscan/findings';

const SMALL = 'whitespace-nowrap rounded-md border border-slate-300 px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:hover:bg-slate-800';
const DOT: Record<string, string> = { critical: 'bg-sev-critical', high: 'bg-sev-high', medium: 'bg-sev-medium', low: 'bg-sev-low', info: 'bg-sev-info' };
const LINK = 'text-teal-700 hover:underline dark:text-teal-400';

function statusText(t: TFn, s: string): string {
  return ({ open: t('待處理'), acked: t('已讀'), suppressed: t('忽略中'), resolved: t('已解決') } as Record<string, string>)[s] ?? s;
}

function Ref({ href }: { href: string }) {
  if (!/^https?:\/\//.test(href)) return <>{href}</>;
  return (
    <a className={LINK} href={href} target="_blank" rel="noreferrer noopener">
      {href}
    </a>
  );
}

/** 點開一列後的細節：說明、怎麼修、規則與分類、參考連結、證據。 */
function FindingDetail({ f, t }: { f: WebFindingView; t: TFn }) {
  return (
    <td colSpan={6} className="space-y-2 px-3 py-3 text-sm">
      {f.detail ? <p className="whitespace-pre-wrap">{t(f.detail)}</p> : null}
      {f.recommendation ? (
        <p>
          <span className="font-medium">{t('怎麼修：')}</span>
          {t(f.recommendation)}
        </p>
      ) : null}
      <p className="text-xs text-slate-500">
        {t('規則 ID')}：<span className="font-mono">{f.rule}</span>
        {f.cwe.length ? ` · CWE：${f.cwe.join(', ')}` : ''}
        {f.cvss != null ? ` · CVSS：${f.cvss}` : ''}
        {` · ${t('第一次看到')}：${f.firstSeenAt.slice(0, 10)}`}
      </p>
      {f.refs.length ? (
        <ul className="list-inside list-disc text-xs">
          {f.refs.map((r) => (
            <li key={r}>
              <Ref href={r} />
            </li>
          ))}
        </ul>
      ) : null}
      <pre className="max-h-48 overflow-auto rounded-md bg-slate-100 p-2 text-xs dark:bg-slate-900">{JSON.stringify(f.evidence, null, 2)}</pre>
    </td>
  );
}

function FindingRow({ f, t, selected, onSelect, open, onOpen }: { f: WebFindingView; t: TFn; selected: boolean; onSelect: (on: boolean) => void; open: boolean; onOpen: () => void }) {
  const where = String(f.location.url ?? '');
  return (
    <tr className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800 [&_td]:px-3 [&_td]:py-2">
      <td>
        <input type="checkbox" aria-label={t('選取')} checked={selected} onChange={(e) => onSelect(e.target.checked)} />
      </td>
      <td className="whitespace-nowrap">
        <span className={`mr-1.5 inline-block h-2.5 w-2.5 rounded-full ${DOT[f.severity] ?? 'bg-slate-400'}`} aria-hidden />
        {sevLabel(t, f.severity)}
      </td>
      <td>
        <button type="button" className="text-left hover:underline" onClick={onOpen} aria-expanded={open}>
          {t(f.title)}
        </button>
        {f.cve ? <span className="ml-2 font-mono text-xs text-slate-500">{f.cve}</span> : null}
      </td>
      <td className="whitespace-nowrap text-xs text-slate-500">{f.scanner}</td>
      <td className="max-w-xs truncate font-mono text-xs" title={where}>
        {where}
      </td>
      <td className="whitespace-nowrap text-xs">{statusText(t, f.status)}</td>
      <td className="whitespace-nowrap text-xs text-slate-500">{f.lastSeenAt.slice(0, 16).replace('T', ' ')}</td>
    </tr>
  );
}

/** 篩選：預設只看待處理與已讀、不含「資訊」等級。 */
function useFiltered(findings: WebFindingView[]) {
  const [show, setShow] = useState({ closed: false, info: false });
  const rows = useMemo(
    () => findings.filter((f) => (show.closed || f.status === 'open' || f.status === 'acked') && (show.info || f.severity !== 'info')),
    [findings, show],
  );
  return { rows, show, setShow };
}

export function WebFindingsTable({ targetId, findings }: { targetId: string; findings: WebFindingView[] }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const { rows, show, setShow } = useFiltered(findings);
  const [sel, setSel] = useState<string[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const act = (body: Record<string, unknown>) =>
    start(async () => {
      setErr(null);
      const r = await apiPost('/api/v1/admin/webscan/findings', { target_id: targetId, ids: sel, ...body });
      if (!r.ok) setErr(t('失敗（HTTP {n}）', { n: r.status }));
      setSel([]);
      router.refresh();
    });
  const empty = findings.length ? t('沒有符合篩選條件的問題。') : t('還沒有發現問題（或還沒掃描過）。');

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="inline-flex items-center gap-1">
          <input type="checkbox" checked={show.info} onChange={(e) => setShow({ ...show, info: e.target.checked })} />
          {t('顯示「資訊」等級')}
        </label>
        <label className="inline-flex items-center gap-1">
          <input type="checkbox" checked={show.closed} onChange={(e) => setShow({ ...show, closed: e.target.checked })} />
          {t('顯示已解決與忽略中')}
        </label>
        <span className="ml-auto flex gap-1">
          <button type="button" className={SMALL} disabled={pending || !sel.length} onClick={() => act({ action: 'ack' })}>
            {t('標為已讀')}
          </button>
          <button type="button" className={SMALL} disabled={pending || !sel.length} onClick={() => act({ action: 'suppress', days: 30 })}>
            {t('忽略 30 天')}
          </button>
          <button type="button" className={SMALL} disabled={pending || !sel.length} onClick={() => act({ action: 'reopen' })}>
            {t('重新開啟')}
          </button>
        </span>
      </div>
      {err ? <p className="text-sm text-red-700 dark:text-red-400">{err}</p> : null}
      {!rows.length ? <p className="text-sm text-slate-500">{empty}</p> : null}
      {rows.length ? (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap [&_th]:px-3 [&_th]:py-2">
              <tr>
                <th>
                  <input type="checkbox" aria-label={t('全選')} checked={sel.length > 0 && sel.length === rows.length} onChange={(e) => setSel(e.target.checked ? rows.map((r) => r.findingId) : [])} />
                </th>
                <th>{t('嚴重度')}</th>
                <th>{t('問題')}</th>
                <th>{t('掃描器')}</th>
                <th>{t('位置')}</th>
                <th>{t('狀態')}</th>
                <th>{t('最後看到')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <Fragment key={f.findingId}>
                  <FindingRow
                    f={f}
                    t={t}
                    selected={sel.includes(f.findingId)}
                    onSelect={(on) => setSel((s) => (on ? [...s, f.findingId] : s.filter((x) => x !== f.findingId)))}
                    open={open === f.findingId}
                    onOpen={() => setOpen(open === f.findingId ? null : f.findingId)}
                  />
                  {open === f.findingId ? (
                    <tr className="border-b border-slate-100 bg-slate-50 dark:border-slate-800 dark:bg-slate-950/40">
                      <td />
                      <FindingDetail f={f} t={t} />
                    </tr>
                  ) : null}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
