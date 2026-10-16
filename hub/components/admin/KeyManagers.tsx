'use client';

// 管理頁：API token 與註冊金鑰的建立／撤銷。明文只在建立後顯示一次。
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';
import { apiDelete, apiPost } from '@/lib/api-client';
import { useT } from '@/lib/i18n/client';

export interface TokenRow {
  id: string;
  name: string;
  hint: string;
  scopes: string[];
  createdAt: string;
  createdBy: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  status: 'active' | 'revoked' | 'expired';
}

export interface EnrollRow {
  id: string;
  name: string;
  hint: string;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
  agents: number;
  status: 'active' | 'revoked';
}

const SCOPES = ['read', 'export', 'mcp'] as const;
const INPUT = 'rounded-md border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900';
const BTN = 'rounded-md bg-teal-600 px-3 py-1 text-sm font-medium text-white hover:bg-teal-700 disabled:opacity-50';
const TABLE = 'overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900';
const HEAD = 'border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap';
const ROW = 'border-b border-slate-100 last:border-0 dark:border-slate-800';

function day(s: string | null): string {
  return s ? s.slice(0, 10) : '—';
}

/** 建立後只顯示一次的明文（附複製按鈕）。 */
export function SecretOnce({ value, note }: { value: string; note: string }) {
  const { t } = useT();
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-800 dark:bg-amber-950/40">
      <p className="mb-2 text-amber-900 dark:text-amber-200">{note}</p>
      <div className="flex flex-wrap items-center gap-2">
        <code className="break-all rounded bg-white px-2 py-1 font-mono text-xs dark:bg-slate-900">{value}</code>
        <button
          type="button"
          className="rounded-md border border-slate-300 px-2 py-1 text-xs dark:border-slate-700"
          onClick={() => {
            void navigator.clipboard?.writeText(value).then(() => setCopied(true));
          }}
        >
          {copied ? t('已複製') : t('複製')}
        </button>
      </div>
    </div>
  );
}

function StatusText({ s }: { s: string }) {
  const { t } = useT();
  if (s === 'active') return <span className="text-green-700 dark:text-green-400">{t('有效')}</span>;
  if (s === 'expired') return <span className="text-slate-500">{t('已過期')}</span>;
  return <span className="text-slate-500">{t('已撤銷')}</span>;
}

export function TokenManager({ items }: { items: TokenRow[] }) {
  const { t } = useT();
  const router = useRouter();
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>(['read']);
  const [days, setDays] = useState('90');
  const [created, setCreated] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, start] = useTransition();
  const create = () =>
    start(async () => {
      setErr(null);
      const r = await apiPost<{ token?: string; error?: string }>('/api/v1/admin/tokens', {
        name: name.trim(),
        scopes,
        expires_days: days === 'never' ? null : Number(days),
      });
      if (!r.ok || !r.data.token) {
        setErr(t('建立失敗：{e}', { e: r.data.error ?? String(r.status) }));
        return;
      }
      setCreated(r.data.token);
      setName('');
      router.refresh();
    });
  const revoke = (id: string) =>
    start(async () => {
      if (!window.confirm(t('撤銷後使用這個 token 的程式會立刻失效，確定？'))) return;
      await apiDelete(`/api/v1/admin/tokens/${encodeURIComponent(id)}`);
      router.refresh();
    });
  return (
    <div className="space-y-3">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim() && scopes.length) create();
        }}
      >
        <label className="text-sm">
          <div className="text-xs text-slate-500">{t('名稱')}</div>
          <input className={INPUT} value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={t('例：Grafana、SIEM 匯出')} />
        </label>
        <fieldset className="text-sm">
          <legend className="text-xs text-slate-500">{t('權限')}</legend>
          <div className="flex gap-3 py-1">
            {SCOPES.map((s) => (
              <label key={s} className="inline-flex items-center gap-1">
                <input type="checkbox" checked={scopes.includes(s)} onChange={(e) => setScopes((x) => (e.target.checked ? [...x, s] : x.filter((y) => y !== s)))} />
                {s === 'read' ? t('讀取 API') : s === 'export' ? t('CSV 匯出') : 'MCP'}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="text-sm">
          <div className="text-xs text-slate-500">{t('有效期限')}</div>
          <select className={INPUT} value={days} onChange={(e) => setDays(e.target.value)}>
            <option value="30">{t('{n} 天', { n: 30 })}</option>
            <option value="90">{t('{n} 天', { n: 90 })}</option>
            <option value="365">{t('{n} 天', { n: 365 })}</option>
            <option value="never">{t('不過期')}</option>
          </select>
        </label>
        <button type="submit" className={BTN} disabled={busy || !name.trim() || !scopes.length}>
          {t('建立 token')}
        </button>
      </form>
      {err ? <p className="text-sm text-red-700 dark:text-red-400">{err}</p> : null}
      {created ? <SecretOnce value={created} note={t('這是唯一一次顯示完整 token，請現在複製保存。用法：Authorization: Bearer <token>')} /> : null}
      {items.length ? (
        <div className={TABLE}>
          <table className="w-full text-left text-sm">
            <thead className={HEAD}>
              <tr>
                <th className="px-3 py-2">{t('名稱')}</th>
                <th className="px-3 py-2">{t('權限')}</th>
                <th className="px-3 py-2">{t('狀態')}</th>
                <th className="px-3 py-2">{t('建立')}</th>
                <th className="px-3 py-2">{t('到期')}</th>
                <th className="px-3 py-2">{t('最後使用')}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className={ROW}>
                  <td className="px-3 py-2">
                    <div>{r.name}</div>
                    <div className="font-mono text-[11px] text-slate-400">{r.hint}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">{r.scopes.join(', ')}</td>
                  <td className="px-3 py-2 text-xs">
                    <StatusText s={r.status} />
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">
                    {day(r.createdAt)} · {r.createdBy}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{r.expiresAt ? day(r.expiresAt) : t('不過期')}</td>
                  <td className="px-3 py-2 text-xs text-slate-500">{day(r.lastUsedAt)}</td>
                  <td className="px-3 py-2 text-right">
                    {r.status === 'active' ? (
                      <button type="button" className="text-xs text-red-700 hover:underline dark:text-red-400" disabled={busy} onClick={() => revoke(r.id)}>
                        {t('撤銷')}
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-slate-500">{t('還沒有 API token。')}</p>
      )}
    </div>
  );
}

export function EnrollKeyManager({ items, hub }: { items: EnrollRow[]; hub: string | null }) {
  const { t } = useT();
  const router = useRouter();
  const [name, setName] = useState('');
  const [created, setCreated] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, start] = useTransition();
  const create = () =>
    start(async () => {
      setErr(null);
      const r = await apiPost<{ key?: string; error?: string }>('/api/v1/admin/enroll-keys', { name: name.trim() });
      if (!r.ok || !r.data.key) {
        setErr(t('建立失敗：{e}', { e: r.data.error ?? String(r.status) }));
        return;
      }
      setCreated(r.data.key);
      setName('');
      router.refresh();
    });
  const revoke = (id: string, agents: number) =>
    start(async () => {
      if (!window.confirm(t('撤銷後，用這把金鑰的 {n} 台主機都會無法上傳，確定？', { n: agents }))) return;
      await apiDelete(`/api/v1/admin/enroll-keys/${encodeURIComponent(id)}`);
      router.refresh();
    });
  return (
    <div className="space-y-3">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) create();
        }}
      >
        <label className="text-sm">
          <div className="text-xs text-slate-500">{t('名稱')}</div>
          <input className={INPUT} value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={t('例：辦公室電腦、正式機房')} />
        </label>
        <button type="submit" className={BTN} disabled={busy || !name.trim()}>
          {t('建立註冊金鑰')}
        </button>
      </form>
      {err ? <p className="text-sm text-red-700 dark:text-red-400">{err}</p> : null}
      {created ? (
        <div className="space-y-2">
          <SecretOnce value={created} note={t('這是唯一一次顯示完整金鑰，請現在複製保存。')} />
          {hub ? <InstallCommandsView hub={hub} keyValue={created} /> : null}
        </div>
      ) : null}
      {items.length ? (
        <div className={TABLE}>
          <table className="w-full text-left text-sm">
            <thead className={HEAD}>
              <tr>
                <th className="px-3 py-2">{t('名稱')}</th>
                <th className="px-3 py-2">{t('主機數')}</th>
                <th className="px-3 py-2">{t('狀態')}</th>
                <th className="px-3 py-2">{t('建立')}</th>
                <th className="px-3 py-2">{t('最後使用')}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className={ROW}>
                  <td className="px-3 py-2">
                    <div>{r.name}</div>
                    <div className="font-mono text-[11px] text-slate-400">{r.hint}</div>
                  </td>
                  <td className="px-3 py-2 tabular-nums">{r.agents}</td>
                  <td className="px-3 py-2 text-xs">
                    <StatusText s={r.status} />
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">
                    {day(r.createdAt)} · {r.createdBy}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{day(r.lastUsedAt)}</td>
                  <td className="px-3 py-2 text-right">
                    {r.status === 'active' ? (
                      <button type="button" className="text-xs text-red-700 hover:underline dark:text-red-400" disabled={busy} onClick={() => revoke(r.id, r.agents)}>
                        {t('撤銷')}
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-slate-500">{t('還沒有註冊金鑰。')}</p>
      )}
    </div>
  );
}

function CmdBlock({ label, cmd }: { label: string; cmd: string }) {
  return (
    <div>
      <div className="mb-1 text-xs text-slate-500">{label}</div>
      <pre className="overflow-x-auto rounded-md bg-slate-900 px-3 py-2 text-xs text-slate-100">
        <code>{cmd}</code>
      </pre>
    </div>
  );
}

/** 安裝指令（金鑰已填好）；跟 lib/install.ts 的 installCommands 同一套格式。 */
export function InstallCommandsView({ hub, keyValue }: { hub: string; keyValue: string }) {
  const { t } = useT();
  return (
    <div className="space-y-2 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
      <CmdBlock label={t('Linux／macOS 伺服器（開機就啟動，需要 sudo）')} cmd={`curl -fsSL ${hub}/install.sh | sh -s -- --key ${keyValue} --service system`} />
      <CmdBlock label={t('Linux／macOS 個人電腦（登入時啟動）')} cmd={`curl -fsSL ${hub}/install.sh | sh -s -- --key ${keyValue} --service user`} />
      <CmdBlock label={t('Windows 伺服器（系統管理員 PowerShell）')} cmd={`$env:ASA_ENROLL_KEY='${keyValue}'; $env:ASA_SERVICE='system'; irm ${hub}/install.ps1 | iex`} />
      <CmdBlock label={t('Windows 個人電腦（PowerShell）')} cmd={`$env:ASA_ENROLL_KEY='${keyValue}'; $env:ASA_SERVICE='user'; irm ${hub}/install.ps1 | iex`} />
      <CmdBlock label={t('已經裝好 asa')} cmd={`asa enroll ${hub} --key ${keyValue}`} />
    </div>
  );
}

/** /install 頁：直接建立一把金鑰並顯示填好的指令。 */
export function InstallKeyMaker({ hub }: { hub: string }) {
  const { t } = useT();
  const [name, setName] = useState('');
  const [key, setKey] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, start] = useTransition();
  return (
    <div className="space-y-3">
      {!key ? (
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            start(async () => {
              const r = await apiPost<{ key?: string; error?: string }>('/api/v1/admin/enroll-keys', { name: name.trim() || t('安裝頁建立') });
              if (r.ok && r.data.key) setKey(r.data.key);
              else setErr(t('建立失敗：{e}', { e: r.data.error ?? String(r.status) }));
            });
          }}
        >
          <label className="text-sm">
            <div className="text-xs text-slate-500">{t('金鑰名稱（選填）')}</div>
            <input className={INPUT} value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={t('例：辦公室電腦、正式機房')} />
          </label>
          <button type="submit" className={BTN} disabled={busy}>
            {t('建立註冊金鑰並產生指令')}
          </button>
        </form>
      ) : (
        <>
          <SecretOnce value={key} note={t('這是唯一一次顯示完整金鑰，請現在複製保存。')} />
          <InstallCommandsView hub={hub} keyValue={key} />
        </>
      )}
      {err ? <p className="text-sm text-red-700 dark:text-red-400">{err}</p> : null}
    </div>
  );
}
