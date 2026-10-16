import Link from 'next/link';
import { headers } from 'next/headers';
import { EnrollKeyManager, TokenManager, type EnrollRow, type TokenRow } from '@/components/admin/KeyManagers';
import { Card } from '@/components/ui/Card';
import { requireAdmin } from '@/lib/auth/require';
import { listApiTokens, listEnrollKeys } from '@/lib/auth/tokens';
import { env } from '@/lib/env';
import { utc } from '@/lib/format';
import { getT } from '@/lib/i18n/server';
import { hubPublicUrl } from '@/lib/install';
import { listAudit } from '@/lib/queries/admin';
import { strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

const TABS = ['keys', 'tokens', 'audit', 'export'] as const;
type Tab = (typeof TABS)[number];

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export default async function AdminPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const raw = Array.isArray(sp.tab) ? sp.tab[0] : sp.tab;
  const tab: Tab = (TABS as readonly string[]).includes(raw ?? '') ? (raw as Tab) : 'keys';
  const label: Record<Tab, string> = { keys: t('註冊金鑰'), tokens: t('API token'), audit: t('稽核紀錄'), export: t('匯出') };
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('管理')}</h1>
        <p className="text-sm text-slate-500">{t('代理程式的註冊金鑰、唯讀 API token、稽核紀錄與 CSV 匯出。')}</p>
      </header>
      <nav className="flex flex-wrap gap-1 border-b border-slate-200 text-sm dark:border-slate-800" aria-label={t('分頁')}>
        {TABS.map((k) => (
          <Link
            key={k}
            href={k === 'keys' ? '/admin' : `/admin?tab=${k}`}
            className={`-mb-px border-b-2 px-3 py-2 ${k === tab ? 'border-teal-600 font-medium text-teal-700 dark:text-teal-400' : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'}`}
            aria-current={k === tab ? 'page' : undefined}
          >
            {label[k]}
          </Link>
        ))}
      </nav>
      {tab === 'keys' ? <KeysTab /> : null}
      {tab === 'tokens' ? <TokensTab /> : null}
      {tab === 'audit' ? <AuditTab action={strParam(sp, 'action', 64)} /> : null}
      {tab === 'export' ? <ExportTab /> : null}
    </div>
  );
}

async function KeysTab() {
  const { t } = await getT();
  const h = await headers();
  const items: EnrollRow[] = (await listEnrollKeys()).map((k) => ({ ...k, createdAt: k.createdAt.toISOString(), lastUsedAt: iso(k.lastUsedAt) }));
  const envKeys = env().clientSecrets.length;
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {t('代理程式用註冊金鑰上傳報告。可以一個部門或一批機器一把；撤銷後用那把金鑰的主機會被拒絕。')}
        {envKeys ? ` ${t('另有 {n} 把來自環境變數 ASA_HUB_CLIENT_SECRETS 的金鑰（不在這裡管理）。', { n: envKeys })}` : ''}
      </p>
      <EnrollKeyManager items={items} hub={hubPublicUrl(h)} />
      <p className="text-sm">
        <Link className="text-teal-700 hover:underline dark:text-teal-400" href="/install">
          {t('→ 安裝頁：各平台一行安裝指令')}
        </Link>
      </p>
    </div>
  );
}

async function TokensTab() {
  const { t } = await getT();
  const items: TokenRow[] = (await listApiTokens()).map((k) => ({
    ...k,
    scopes: [...k.scopes],
    createdAt: k.createdAt.toISOString(),
    expiresAt: iso(k.expiresAt),
    lastUsedAt: iso(k.lastUsedAt),
  }));
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        {t('給其他系統用的唯讀 token：讀取 API（/api/v1/…）、CSV 匯出、Hub MCP（/api/mcp）。token 不能做任何寫入或管理動作。')}
      </p>
      <TokenManager items={items} />
    </div>
  );
}

async function AuditTab({ action }: { action?: string }) {
  const { t } = await getT();
  const rows = await listAudit({ limit: 200, action });
  return (
    <div className="space-y-3">
      <form className="flex flex-wrap items-end gap-2 text-sm" action="/admin">
        <input type="hidden" name="tab" value="audit" />
        <label>
          <div className="text-xs text-slate-500">{t('動作開頭')}</div>
          <input
            name="action"
            defaultValue={action ?? ''}
            placeholder="token. / enroll_key. / action. / ingest."
            className="rounded-md border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
          />
        </label>
        <button type="submit" className="rounded-md border border-slate-300 px-3 py-1 dark:border-slate-700">
          {t('篩選')}
        </button>
        <a className="ml-auto text-teal-700 hover:underline dark:text-teal-400" href="/api/v1/export/audit.csv">
          {t('下載 CSV')}
        </a>
      </form>
      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-xs text-slate-500 dark:border-slate-800 [&_th]:whitespace-nowrap">
            <tr>
              <th className="px-3 py-2">{t('時間')}</th>
              <th className="px-3 py-2">{t('操作者')}</th>
              <th className="px-3 py-2">{t('動作')}</th>
              <th className="px-3 py-2">{t('對象')}</th>
              <th className="px-3 py-2">{t('來源 IP')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b border-slate-100 align-top last:border-0 dark:border-slate-800">
                <td className="px-3 py-2 whitespace-nowrap text-xs text-slate-500">{utc(r.at)}</td>
                <td className="px-3 py-2 text-xs">{r.actor}</td>
                <td className="px-3 py-2 font-mono text-xs">{r.action}</td>
                <td className="px-3 py-2 text-xs">
                  {r.targetType ? `${r.targetType}:${r.targetId ?? ''}` : '—'}
                  {r.details ? <div className="mt-0.5 max-w-md truncate text-slate-400">{JSON.stringify(r.details)}</div> : null}
                </td>
                <td className="px-3 py-2 text-xs text-slate-500">{r.sourceIp ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length ? <p className="p-3 text-sm text-slate-500">{t('沒有符合的紀錄。')}</p> : null}
      </div>
    </div>
  );
}

async function ExportTab() {
  const { t } = await getT();
  const links: [string, string, string][] = [
    ['findings', t('發現'), t('待處理的發現（可加 ?status=resolved 等同 /findings 的篩選）')],
    ['agents', t('代理程式'), t('主機、版本、分數與最後回報時間')],
    ['actions', t('動作'), t('遠端動作與審核結果')],
    ['audit', t('稽核紀錄'), t('最近 1000 筆')],
  ];
  return (
    <Card>
      <ul className="space-y-2 text-sm">
        {links.map(([k, name, desc]) => (
          <li key={k}>
            <a className="font-medium text-teal-700 hover:underline dark:text-teal-400" href={`/api/v1/export/${k}.csv`}>
              {name} (.csv)
            </a>
            <span className="ml-2 text-slate-500">{desc}</span>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-slate-500">
        {t('其他系統可以用有 export 權限的 API token：curl -H "Authorization: Bearer <token>" <hub>/api/v1/export/findings.csv')}
      </p>
    </Card>
  );
}
