'use client';

// 「設定與金鑰 → 網站掃描」：允許掃描的內網網段、速率與逾時、停用的掃描器、連上來的掃描端、部署方式。
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition, type ReactNode } from 'react';
import { errorText } from '@/components/webscan/labels';
import { Hint } from '@/components/ui/Hint';
import { apiPut } from '@/lib/api-client';
import { since } from '@/lib/format';
import { useT } from '@/lib/i18n/client';
import { SCANNER_INFO, WEBSCAN_SCANNERS, type WebscanScanner } from '@/lib/webscan/scanners';
import type { WebscanView } from '@/lib/webscan/view';

const INPUT = 'w-full rounded-md border border-slate-300 bg-white px-2 py-1 font-mono text-xs dark:border-slate-700 dark:bg-slate-900';
const BTN = 'whitespace-nowrap rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const BOX = 'rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900';
const CODE = 'block overflow-x-auto whitespace-pre rounded-md bg-slate-100 px-2 py-1 font-mono text-xs dark:bg-slate-800';

const lines = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block space-y-1 text-sm">
      <span className="flex items-center text-xs text-slate-500">
        {label}
        {hint ? <Hint text={hint} /> : null}
      </span>
      {children}
    </label>
  );
}

export function WebScanSettings({ view }: { view: WebscanView }) {
  const { t } = useT();
  const router = useRouter();
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const s = view.settings;
  const [form, setForm] = useState({
    cidrs: s.internal_cidrs.join('\n'),
    rate: String(s.rate_per_sec),
    concurrency: String(s.concurrency),
    timeout: String(s.timeout_minutes),
    disabled: s.disabled_scanners as WebscanScanner[],
  });
  const save = () =>
    start(async () => {
      setMsg(null);
      const r = await apiPut<{ error?: string }>('/api/v1/admin/webscan/settings', {
        internal_cidrs: lines(form.cidrs),
        rate_per_sec: Number(form.rate),
        concurrency: Number(form.concurrency),
        timeout_minutes: Number(form.timeout),
        disabled_scanners: form.disabled,
      });
      setMsg(r.ok ? { ok: true, text: t('已儲存') } : { ok: false, text: r.data.error?.startsWith('invalid:') ? t('格式不對：{f}', { f: r.data.error.slice(8) }) : errorText(t, r.data.error, r.status) });
      if (r.ok) router.refresh();
    });

  return (
    <div className="space-y-4">
      <section className={BOX}>
        <h2 className="text-base font-semibold">{t('掃描端')}</h2>
        <p className="mt-1 text-sm text-slate-500">{t('掃描端（webscan runner）是另外一個容器：它向 Hub 領工作、執行開源掃描器、把結果傳回來。Hub 本身不連你的網站，也不需要 Docker 權限。')}</p>
        {view.runners.length ? (
          <table className="mt-3 w-full text-left text-sm">
            <thead className="text-xs text-slate-500 [&_th]:px-2 [&_th]:py-1">
              <tr>
                <th>{t('名稱')}</th>
                <th>{t('主機')}</th>
                <th>{t('版本')}</th>
                <th>{t('掃描器')}</th>
                <th>{t('狀態')}</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1">
              {view.runners.map((r) => (
                <tr key={r.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td>{r.name}</td>
                  <td className="font-mono text-xs">{r.hostname || '—'}</td>
                  <td className="text-xs">{r.version || '—'}</td>
                  <td className="text-xs">{r.capabilities.map((c) => `${c.scanner} ${c.version}`).join(', ') || '—'}</td>
                  <td className="whitespace-nowrap text-xs">{r.online ? <span className="text-emerald-700 dark:text-emerald-400">{t('在線')}</span> : <span className="text-slate-500">{t('離線（{t}）', { t: since(r.lastSeenAt, t) })}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="mt-3 text-sm text-amber-700 dark:text-amber-400">{t('還沒有掃描端連上來。')}</p>
        )}
        <div className="mt-3 space-y-1 text-sm">
          <div className="font-medium">{t('部署（跟 Hub 在同一台）')}</div>
          <p className="text-slate-500">{t('在 .env 設 AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN（至少 32 字元，Hub 與掃描端共用），改用含網站掃描的 compose 檔：')}</p>
          <code className={CODE}>{'docker compose -f docker/compose.standalone.webscan.yml --env-file .env up -d'}</code>
          <p className="text-slate-500">
            {t('放在其他主機（例如要掃另一個內網區段）：到')}{' '}
            <Link className="text-teal-700 hover:underline dark:text-teal-400" href="/admin?tab=tokens">
              {t('API token')}
            </Link>{' '}
            {t('建一個勾「網站掃描端」的權杖，再用 AI_SECURITY_MONITOR_WEBSCAN_HUB_URL 指向這個 Hub。')}
          </p>
          <p className="text-xs text-slate-500">{view.composeTokenConfigured ? t('這台 Hub 已設定 compose 權杖。') : t('這台 Hub 還沒設定 compose 權杖。')}</p>
        </div>
      </section>

      <section className={BOX}>
        <h2 className="text-base font-semibold">{t('掃描範圍與速度')}</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <Field label={t('允許掃描的內網網段')} hint={t('網址解析到內網位址（10.x、172.16–31.x、192.168.x、100.64.x、fc00::/7）時，只有落在這些網段內才會掃。每行一個 IP 或 CIDR，例 192.168.1.0/24。')}>
            <textarea className={INPUT} rows={4} value={form.cidrs} onChange={(e) => setForm({ ...form, cidrs: e.target.value })} placeholder="192.168.1.0/24" />
          </Field>
          <div className="space-y-3">
            <Field label={t('每秒最多幾個請求')} hint={t('每個掃描器各自的上限；網站比較脆弱就調低。')}>
              <input className={INPUT} type="number" min={1} max={50} value={form.rate} onChange={(e) => setForm({ ...form, rate: e.target.value })} />
            </Field>
            <Field label={t('同時幾個連線')}>
              <input className={INPUT} type="number" min={1} max={10} value={form.concurrency} onChange={(e) => setForm({ ...form, concurrency: e.target.value })} />
            </Field>
            <Field label={t('一次掃描最長幾分鐘')}>
              <input className={INPUT} type="number" min={1} max={180} value={form.timeout} onChange={(e) => setForm({ ...form, timeout: e.target.value })} />
            </Field>
          </div>
        </div>
        <fieldset className="mt-3 text-sm">
          <legend className="text-xs text-slate-500">{t('停用的掃描器')}</legend>
          <div className="flex flex-wrap gap-4 py-1">
            {WEBSCAN_SCANNERS.map((k) => (
              <label key={k} className="inline-flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={form.disabled.includes(k)}
                  onChange={(e) => setForm({ ...form, disabled: e.target.checked ? [...form.disabled, k] : form.disabled.filter((x) => x !== k) })}
                />
                <span className="font-mono">{k}</span>
                <span className="text-xs text-slate-500">{SCANNER_INFO[k].license}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="mt-3 flex items-center gap-3">
          <button type="button" className={BTN} disabled={pending} onClick={save}>
            {t('儲存')}
          </button>
          {msg ? <span className={`text-sm ${msg.ok ? 'text-teal-700 dark:text-teal-400' : 'text-red-700 dark:text-red-400'}`}>{msg.text}</span> : null}
        </div>
      </section>
    </div>
  );
}
