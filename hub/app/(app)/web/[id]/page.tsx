import Link from 'next/link';
import { notFound } from 'next/navigation';
import { JobsTable } from '@/components/webscan/JobsTable';
import { proofLabel, verifyMethodLabel } from '@/components/webscan/labels';
import { DeleteTargetButton, ScanButtons, VerifyPanel } from '@/components/webscan/TargetActions';
import { WebFindingsTable } from '@/components/webscan/WebFindingsTable';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { Hint } from '@/components/ui/Hint';
import { requireAdmin } from '@/lib/auth/require';
import { getDb } from '@/lib/db';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import { targetDetail, type TargetDetail } from '@/lib/webscan/view';

export const dynamic = 'force-dynamic';

type Fingerprint = { status_code?: number | null; title?: string; webserver?: string; tech?: string[]; ip?: string };

/** httpx 的被動指紋：狀態碼、標題、伺服器、技術、IP（還沒掃過就不顯示）。 */
function FingerprintList({ fp, t }: { fp: Fingerprint; t: TFn }) {
  if (fp.status_code == null && !fp.webserver && !fp.tech?.length) return null;
  const rows: [string, string][] = [
    [t('狀態碼'), fp.status_code != null ? String(fp.status_code) : '—'],
    [t('網頁標題'), fp.title || '—'],
    [t('網頁伺服器'), fp.webserver || '—'],
    [t('使用的技術'), fp.tech?.length ? fp.tech.join('、') : '—'],
    ['IP', fp.ip || '—'],
  ];
  return (
    <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-slate-500">{k}</dt>
          <dd className="break-all">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function ProofCard({ d, t }: { d: TargetDetail; t: TFn }) {
  const x = d.target;
  const internal = x.verifyMethod === 'internal-cidr';
  const note = d.proven ? t('已驗證，可以做主動掃描。驗證碼請一直留著，過期前重新檢查一次即可。') : internal ? t('這個網址在內網白名單裡，管理員已聲明是自己的網段，不需要另外驗證。') : null;
  return (
    <Card title={t('證明網站是你的')} className="min-w-0">
      {note ? <p className="text-sm text-slate-600 dark:text-slate-300">{note}</p> : null}
      {!d.proven && !internal ? <VerifyPanel targetId={x.id} token={x.verifyToken} txtName={d.txtName} url={x.url} host={x.host} /> : null}
      {x.verifyError && !d.proven ? <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">{t('上次檢查：{e}', { e: x.verifyError })}</p> : null}
    </Card>
  );
}

function RawOutputs({ d, t }: { d: TargetDetail; t: TFn }) {
  const arts = d.latest?.artifacts ?? [];
  if (!arts.length) return null;
  return (
    <div className="mt-3 text-sm">
      <span className="text-slate-500">{t('最近一次的原始輸出：')}</span>
      {arts.map((a) => (
        <a key={a.id} className="ml-3 text-teal-700 hover:underline dark:text-teal-400" href={`/api/v1/admin/webscan/artifacts/${a.id}`}>
          {a.scanner}
          {a.truncated ? `（${t('已截斷')}）` : ''}
        </a>
      ))}
    </div>
  );
}

export default async function WebTargetPage({ params }: { params: Promise<{ id: string }> }) {
  await requireAdmin();
  const { t } = await getT();
  const { id } = await params;
  const d = await targetDetail(getDb(), id);
  if (!d) notFound();
  const x = d.target;
  const p = proofLabel(t, { verifyMethod: x.verifyMethod, proven: d.proven, proofExpired: d.proofExpired });
  const lastScan = x.lastScanAt ? t('最後掃描 {t}', { t: since(x.lastScanAt, t) }) : t('還沒掃過');
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <Link className="text-sm text-teal-700 hover:underline dark:text-teal-400" href="/web">
          {t('← 網站掃描')}
        </Link>
        <h1 className="break-all font-mono text-xl font-semibold">{x.url}</h1>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge tone={p.tone}>{p.text}</Badge>
          <Hint text={p.hint} />
          {x.verifyMethod ? <span className="text-slate-500">{t('驗證方式：{m}', { m: verifyMethodLabel(t, x.verifyMethod) })}</span> : null}
          {d.proven && d.proofExpiresAt ? <span className="text-slate-500">{t('有效到 {d}', { d: d.proofExpiresAt.slice(0, 10) })}</span> : null}
          <span className="text-slate-500">{lastScan}</span>
          <span className="ml-auto">
            <DeleteTargetButton targetId={x.id} />
          </span>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={t('掃描')} className="min-w-0">
          <ScanButtons targetId={x.id} canActive={d.proven || x.verifyMethod === 'internal-cidr'} runnersOnline={d.runnersOnline} />
          <FingerprintList fp={x.fingerprint as Fingerprint} t={t} />
        </Card>
        <ProofCard d={d} t={t} />
      </div>

      <Card title={t('發現的問題')}>
        <WebFindingsTable targetId={x.id} findings={d.findings} />
      </Card>

      <Card title={t('掃描紀錄')}>
        <JobsTable t={t} jobs={d.jobs} />
        <RawOutputs d={d} t={t} />
      </Card>
    </div>
  );
}
