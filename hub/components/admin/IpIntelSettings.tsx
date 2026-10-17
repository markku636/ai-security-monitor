'use client';

// 設定頁「外部情資」分頁：各來源的開關、金鑰（只寫不讀）、今日額度。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';
import type { ProviderId, SourcesConfigStatus } from '@/lib/ipintel/types';

const INPUT = 'w-full rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900';
const BTN = 'shrink-0 whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const SMALL = 'rounded-md border border-slate-300 px-2 py-0.5 text-xs dark:border-slate-700 disabled:opacity-50';

export function IpIntelSettings({ status }: { status: SourcesConfigStatus }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [drafts, setDrafts] = useState<Partial<Record<ProviderId, string>>>({});
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const save = (body: { keys?: Partial<Record<ProviderId, string | null>>; disabled?: ProviderId[] }) => {
    setMsg(null);
    start(async () => {
      const r = await apiPost('/api/v1/admin/ip-intel', body);
      if (!r.ok) {
        setMsg({ ok: false, text: t('儲存失敗（HTTP {n}）', { n: r.status }) });
        return;
      }
      setDrafts({});
      setMsg({ ok: true, text: t('已儲存') });
      router.refresh();
    });
  };

  const disabled = status.providers.filter((p) => !p.enabled).map((p) => p.id);
  const toggle = (id: ProviderId, on: boolean) => save({ disabled: on ? disabled.filter((x) => x !== id) : [...disabled, id] });
  const keyText = (k: 'required' | 'optional' | 'none') =>
    k === 'required' ? t('需要金鑰') : k === 'optional' ? t('金鑰選填（有金鑰額度較高）') : t('不需要金鑰');

  return (
    <div className="space-y-3">
      {!status.lookupsEnabled ? (
        <p className="rounded-md border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          {t('外部查詢已被關閉（ASA_HUB_IP_LOOKUPS=off）。')}
        </p>
      ) : null}
      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap">
            <tr>
              <th className="px-3 py-2">{t('來源')}</th>
              <th className="px-3 py-2">{t('啟用')}</th>
              <th className="px-3 py-2">{t('金鑰')}</th>
              <th className="px-3 py-2" title={t('hub 自己限制的每日呼叫次數，避免燒光免費額度')}>
                {t('今日用量')}
              </th>
            </tr>
          </thead>
          <tbody>
            {status.providers.map((p) => (
              <tr key={p.id} className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
                <td className="px-3 py-2">
                  <div className="font-medium">{p.name}</div>
                  <div className="text-xs text-slate-500">{keyText(p.key)}</div>
                  {p.id === 'rdns' ? <div className="text-xs text-slate-500">{t('用 hub 主機自己的 DNS 反查，不經第三方網站')}</div> : null}
                </td>
                <td className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={p.enabled}
                    disabled={pending}
                    onChange={(e) => toggle(p.id, e.target.checked)}
                    aria-label={t('啟用 {name}', { name: p.name })}
                  />
                </td>
                <td className="px-3 py-2">
                  {p.key === 'none' ? (
                    <span className="text-xs text-slate-400">—</span>
                  ) : p.keySource === 'env' ? (
                    <span className="text-xs text-slate-500">
                      {t('來自環境變數 {env}', { env: p.env ?? '' })} · <code>{p.keyHint}</code>
                    </span>
                  ) : (
                    <div className="flex min-w-64 flex-col gap-1">
                      {p.keyHint ? (
                        <div className="flex items-center gap-2 text-xs text-slate-500">
                          <span>
                            {t('已設定')} <code>{p.keyHint}</code>
                          </span>
                          <button type="button" className={SMALL} disabled={pending} onClick={() => save({ keys: { [p.id]: null } })}>
                            {t('清除')}
                          </button>
                        </div>
                      ) : null}
                      <div className="flex items-center gap-2">
                        <input
                          type="password"
                          autoComplete="off"
                          className={INPUT}
                          placeholder={p.keyHint ? t('貼上新金鑰取代') : t('貼上金鑰')}
                          value={drafts[p.id] ?? ''}
                          onChange={(e) => setDrafts({ ...drafts, [p.id]: e.target.value })}
                        />
                        <button
                          type="button"
                          className={BTN}
                          disabled={pending || !drafts[p.id]?.trim()}
                          onClick={() => save({ keys: { [p.id]: drafts[p.id]!.trim() } })}
                        >
                          {t('儲存')}
                        </button>
                      </div>
                      {p.signup ? (
                        <a href={p.signup} target="_blank" rel="noreferrer noopener" className="text-xs text-teal-700 hover:underline dark:text-teal-300">
                          {t('→ 去 {name} 申請免費金鑰', { name: p.name })}
                        </a>
                      ) : null}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 text-xs tabular-nums text-slate-500">
                  {p.usedToday} / {p.quota}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {msg ? <p className={`text-sm ${msg.ok ? 'text-green-700 dark:text-green-400' : 'text-red-600'}`}>{msg.text}</p> : null}
    </div>
  );
}
