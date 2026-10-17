'use client';

// 「新增主機」頁：待核准的主機（免金鑰加入申請，每 10 秒自動更新）、自動核准網段設定、可複製的指令區塊。
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, useTransition } from 'react';
import { Hint } from '@/components/ui/Hint';
import { apiPost, apiPut } from '@/lib/api-client';
import { utc } from '@/lib/format';
import { useT } from '@/lib/i18n/client';

export interface EnrollRequestItem {
  id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  agent_id: string;
  known_agent: boolean;
  hostname: string;
  os_family: string | null;
  os_name: string | null;
  os_version: string | null;
  arch: string | null;
  agent_version: string | null;
  ips: string[];
  source_ip: string | null;
  request_code: string;
  accept_remote_actions: boolean;
  auto_approved: boolean;
  created_at: string;
  decided_at: string | null;
  decided_by: string | null;
  reason: string | null;
  expires_at: string;
  claimed_at: string | null;
}

const BTN = 'rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const BTN_DANGER = 'rounded-md border border-red-300 px-3 py-1 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950/40';
const SMALL = 'rounded-md border border-slate-300 px-2 py-0.5 text-xs dark:border-slate-700 disabled:opacity-50';
const PILL = 'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium';
const POLL_MS = 10_000;

/** 指令區塊＋複製按鈕。 */
export function CopyBlock({ label, value }: { label: string; value: string }) {
  const { t } = useT();
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2 text-xs text-slate-500">
        <span>{label}</span>
        <button
          type="button"
          className={SMALL}
          onClick={() => {
            void navigator.clipboard?.writeText(value).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            });
          }}
        >
          {copied ? t('已複製') : t('複製')}
        </button>
      </div>
      <pre className="overflow-x-auto rounded-md bg-slate-900 px-3 py-2 text-xs text-slate-100">
        <code>{value}</code>
      </pre>
    </div>
  );
}

function osText(r: EnrollRequestItem): string {
  const name = r.os_name || r.os_family || '—';
  return [name, r.os_version, r.arch].filter(Boolean).join(' · ');
}

function StatusPill({ s }: { s: EnrollRequestItem['status'] }) {
  const { t } = useT();
  const map = {
    pending: ['bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300', t('待核准')],
    approved: ['bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300', t('已核准')],
    rejected: ['bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300', t('已拒絕')],
    expired: ['bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400', t('已過期')],
  } as const;
  const [cls, text] = map[s];
  return <span className={`${PILL} ${cls}`}>{text}</span>;
}

/** 待核准的主機：勾選＋整批核准／拒絕；頁面開著時每 10 秒更新一次。 */
export function EnrollRequestsPanel({ initial }: { initial: EnrollRequestItem[] }) {
  const { t } = useT();
  const router = useRouter();
  const [items, setItems] = useState(initial);
  const [showAll, setShowAll] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [busy, start] = useTransition();

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/v1/admin/enroll-requests?status=${showAll ? 'all' : 'pending'}`, { credentials: 'same-origin', cache: 'no-store' });
      if (!res.ok) return;
      const data = (await res.json()) as { items: EnrollRequestItem[] };
      setItems(data.items);
      setPicked((p) => p.filter((id) => data.items.some((x) => x.id === id && x.status === 'pending')));
      setUpdatedAt(new Date().toISOString());
    } catch {
      // 網路斷了就等下一輪
    }
  }, [showAll]);

  useEffect(() => {
    void load();
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') void load();
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  const pending = items.filter((x) => x.status === 'pending');
  const allPicked = pending.length > 0 && pending.every((x) => picked.includes(x.id));

  const decide = (ids: string[], decision: 'approve' | 'reject') =>
    start(async () => {
      if (!ids.length) return;
      let reason: string | undefined;
      if (decision === 'reject') {
        const r = window.prompt(t('拒絕 {n} 台主機。要附上原因嗎？（選填，電腦端會看到）', { n: ids.length }), '');
        if (r === null) return;
        reason = r.trim() || undefined;
      }
      setMsg(null);
      const r = await apiPost<{ updated?: number; error?: string }>('/api/v1/admin/enroll-requests/decide', { ids, decision, ...(reason ? { reason } : {}) });
      if (!r.ok) {
        setMsg({ ok: false, text: t('操作失敗：{e}', { e: r.data.error ?? String(r.status) }) });
        return;
      }
      setMsg({
        ok: true,
        text: decision === 'approve' ? t('已核准 {n} 台，電腦端下次詢問（約 15 秒內）就會完成加入。', { n: r.data.updated ?? 0 }) : t('已拒絕 {n} 台。', { n: r.data.updated ?? 0 }),
      });
      setPicked([]);
      await load();
      router.refresh();
    });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BTN} disabled={busy || !picked.length} onClick={() => decide(picked, 'approve')}>
          {t('核准勾選的 {n} 台', { n: picked.length })}
        </button>
        <button type="button" className={BTN_DANGER} disabled={busy || !picked.length} onClick={() => decide(picked, 'reject')}>
          {t('拒絕勾選的 {n} 台', { n: picked.length })}
        </button>
        <label className="ml-auto inline-flex items-center gap-1 text-xs text-slate-500">
          <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
          {t('也顯示已處理的')}
        </label>
        <span className="text-xs text-slate-400" title={t('頁面開著時每 10 秒自動更新')}>
          {updatedAt ? t('更新於 {at}', { at: utc(updatedAt) }) : t('每 10 秒自動更新')}
        </span>
      </div>
      {msg ? <p className={`text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}>{msg.text}</p> : null}
      {items.length ? (
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap">
              <tr>
                <th className="px-3 py-2">
                  <input
                    type="checkbox"
                    aria-label={t('全選')}
                    checked={allPicked}
                    disabled={!pending.length}
                    onChange={(e) => setPicked(e.target.checked ? pending.map((x) => x.id) : [])}
                  />
                </th>
                <th className="px-3 py-2">{t('主機')}</th>
                <th className="px-3 py-2">
                  {t('申請碼')}
                  <Hint text={t('電腦端畫面上也會顯示一組申請碼；兩邊一樣才是同一台，請先對照再核准。')} />
                </th>
                <th className="px-3 py-2">{t('作業系統')}</th>
                <th className="px-3 py-2">{t('IP 位址')}</th>
                <th className="px-3 py-2">
                  {t('來源 IP')}
                  <Hint text={t('這個申請實際從哪個網路位址送進來（Hub 看到的連線來源）。')} />
                </th>
                <th className="px-3 py-2">{t('申請時間')}</th>
                <th className="px-3 py-2">{t('程式版本')}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
                  <td className="px-3 py-2">
                    {r.status === 'pending' ? (
                      <input
                        type="checkbox"
                        aria-label={t('選取 {host}', { host: r.hostname })}
                        checked={picked.includes(r.id)}
                        onChange={(e) => setPicked((p) => (e.target.checked ? [...p, r.id] : p.filter((x) => x !== r.id)))}
                      />
                    ) : null}
                  </td>
                  <td className="px-3 py-2">
                    <div className="font-medium">{r.hostname}</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {r.status !== 'pending' ? <StatusPill s={r.status} /> : null}
                      {r.known_agent ? (
                        <span
                          className={`${PILL} cursor-help bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300`}
                          title={t('這台主機以前就加入過（同一個 agent id）。可能是重灌或重新安裝；不確定就先問使用者。')}
                        >
                          {t('重新加入')}
                        </span>
                      ) : null}
                      {r.auto_approved ? (
                        <span className={`${PILL} cursor-help bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-300`} title={t('來源 IP 在「自動核准的網段」內，所以不用人按就核准了。')}>
                          {t('自動核准')}
                        </span>
                      ) : null}
                      {r.accept_remote_actions ? (
                        <span className={`${PILL} cursor-help bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300`} title={t('這台主機願意執行你核准的封鎖 IP、關閉 port 等動作。')}>
                          {t('接受遠端動作')}
                        </span>
                      ) : null}
                    </div>
                    {r.reason ? <div className="mt-1 text-xs text-slate-500">{t('原因：{r}', { r: r.reason })}</div> : null}
                  </td>
                  <td className="px-3 py-2 font-mono text-base font-semibold tracking-wider">{r.request_code}</td>
                  <td className="px-3 py-2 text-xs">{osText(r)}</td>
                  <td className="px-3 py-2 font-mono text-xs">{r.ips.length ? r.ips.slice(0, 4).join(', ') + (r.ips.length > 4 ? ' …' : '') : '—'}</td>
                  <td className="px-3 py-2 font-mono text-xs">{r.source_ip ?? '—'}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-500">{utc(r.created_at)}</td>
                  <td className="px-3 py-2 text-xs text-slate-500">{r.agent_version ?? '—'}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-right">
                    {r.status === 'pending' ? (
                      <span className="inline-flex gap-2">
                        <button type="button" className={SMALL} disabled={busy} onClick={() => decide([r.id], 'approve')}>
                          {t('核准')}
                        </button>
                        <button type="button" className={`${SMALL} text-red-700 dark:text-red-400`} disabled={busy} onClick={() => decide([r.id], 'reject')}>
                          {t('拒絕')}
                        </button>
                      </span>
                    ) : (
                      <span className="text-xs text-slate-400">{r.decided_by ?? ''}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-slate-500">{t('目前沒有待核准的主機。電腦端執行免金鑰安裝後，申請會出現在這裡。')}</p>
      )}
    </div>
  );
}

/** 自動核准的網段：一行一個 CIDR；存檔時 Hub 會檢查格式並正規化。 */
export function AutoApproveForm({ initial, peerIpAvailable }: { initial: string[]; peerIpAvailable: boolean }) {
  const { t } = useT();
  const router = useRouter();
  const [text, setText] = useState(initial.join('\n'));
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, start] = useTransition();
  const save = () =>
    start(async () => {
      setMsg(null);
      const list = text
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const r = await apiPut<{ auto_approve_cidrs?: string[]; error?: string; value?: string }>('/api/v1/admin/enroll-settings', { auto_approve_cidrs: list });
      if (!r.ok) {
        const e = r.data.error;
        setMsg({
          ok: false,
          text:
            e === 'cidr_too_broad'
              ? t('「{v}」範圍太大（IPv4 至少要 /8、IPv6 至少要 /16），請改小一點。', { v: r.data.value ?? '' })
              : e === 'bad_cidr'
                ? t('「{v}」不是正確的網段寫法。例：192.168.1.0/24、10.0.0.5', { v: r.data.value ?? '' })
                : t('儲存失敗（HTTP {n}）', { n: r.status }),
        });
        return;
      }
      setText((r.data.auto_approve_cidrs ?? []).join('\n'));
      setMsg({ ok: true, text: t('已儲存') });
      router.refresh();
    });
  return (
    <div className="space-y-2">
      {!peerIpAvailable ? (
        <p className="rounded-md border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          {t('目前拿不到可信的連線來源 IP（反向代理後面要設 ASA_HUB_TRUST_PROXY），所以自動核准不會生效，申請一律要人工核准。')}
        </p>
      ) : null}
      <textarea
        className="h-28 w-full rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={'192.168.10.0/24\n10.20.0.0/16'}
        aria-label={t('自動核准的網段')}
        spellCheck={false}
      />
      <div className="flex items-center gap-3">
        <button type="button" className={BTN} disabled={busy} onClick={save}>
          {t('儲存網段')}
        </button>
        {msg ? <span className={`text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'}`}>{msg.text}</span> : null}
      </div>
    </div>
  );
}
