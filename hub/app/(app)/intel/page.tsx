import Link from 'next/link';
import { FeedSyncButton } from '@/components/security/FeedSyncButton';
import { IndicatorDetails } from '@/components/security/IndicatorDetails';
import { DirectionBadge, VerdictChip, directionLabel } from '@/components/security/Verdict';
import { Badge } from '@/components/ui/Badge';
import { Hint } from '@/components/ui/Hint';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { SearchBox } from '@/components/ui/Filters';
import { requireAdmin } from '@/lib/auth/require';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import { mirrorable, readMeta, refreshMs, syncInBackground, type MirrorMeta } from '@/lib/intel/mirror';
import { feedGroup, loadRegistry, type FeedEntry } from '@/lib/intel/registry';
import { listAgents } from '@/lib/queries/agents';
import { strParam } from '@/lib/queries/params';
import { IntelUsageSetting } from '@/components/admin/IntelUsageSetting';
import { getIntelUsage } from '@/lib/intel/usage';
import { getDb } from '@/lib/db';
import { feedHitStats } from '@/lib/queries/intel';

export const dynamic = 'force-dynamic';

type Stats = Awaited<ReturnType<typeof feedHitStats>>;

function groupTitle(t: TFn, g: ReturnType<typeof feedGroup>): string {
  return {
    threat: t('威脅指標（IP／網段）'),
    dns: t('惡意網域與加密 DNS 端點'),
    geo: t('地理位置與 ASN'),
    vuln: t('漏洞資料'),
    lookup: t('線上名譽查詢（需自備 API key，預設關閉）'),
  }[g];
}

/** Hub 不鏡像的來源：說明為什麼、要怎麼更新。 */
function NotMirrored({ t, f }: { t: TFn; f: FeedEntry }) {
  const api = f.format === 'lookup-api' || f.kind === 'lookup';
  let label: string;
  let hint: string;
  if (!api && f.enabled_default && !f.license.commercial_ok) {
    // 只限非商業用途：Hub 設成公司／商業用途時不下載
    label = t('只限非商用，Hub 沒有下載');
    hint = t('這份清單只准個人或非營利使用；Hub 選的是「公司／商業用途」，所以不下載也不給主機。要用的話在上方「情資來源授權」改成個人／非商業用途。');
  } else if (!api && !f.enabled_default) {
    // 預設關閉的清單：Hub 不下載；哪台主機自己開了，就由那台直接向廠商下載
    label = t('預設關閉，Hub 不下載');
    hint = t('這份清單預設沒有啟用，所以 Hub 不會下載。在主機上啟用後，那台電腦會直接向廠商下載並照更新間隔自動更新。');
  } else if (f.kind === 'lookup') {
    // 線上名譽查詢：查某個 IP 時才問廠商
    label = t('查詢時即時取得');
    hint = t('這是線上查詢服務，沒有清單要下載：查某個 IP 時才去問廠商，拿到的就是最新結果，不需要手動更新。');
  } else if (api) {
    // 線上漏洞資料庫：每次掃描都直接查
    label = t('掃描時即時查詢');
    hint = t('這是線上資料庫，沒有清單要下載：主機每次漏洞掃描都直接查最新資料，不需要手動更新。要現在就重查，在那台電腦執行 ai-security-monitor scan，或按桌面版的「立即掃描」。');
  } else {
    return <span className="text-slate-400">{t('不鏡像')}</span>;
  }
  return (
    <span className="inline-flex items-center text-slate-500">
      {label}
      <Hint text={hint} />
    </span>
  );
}

/** 這份清單在 hub 鏡像的狀態（最後同步、大小、錯誤）。 */
function MirrorCell({ t, f, m, nc }: { t: TFn; f: FeedEntry; m: MirrorMeta | null; nc: boolean }) {
  if (!mirrorable(f, nc)) return <NotMirrored t={t} f={f} />;
  if (!m)
    return (
      <div className="space-y-1">
        <span className="text-slate-400">{t('尚未同步')}</span>
        <div>
          <FeedSyncButton only={[f.id]} compact />
        </div>
      </div>
    );
  const stale = m.checked_at ? Date.now() - Date.parse(m.checked_at) > refreshMs(f.refresh_interval) * 3 : true;
  return (
    <>
      <div>
        {m.fetched_at ? since(new Date(m.fetched_at), t) : '—'}
        {m.entries != null ? <span className="text-slate-500"> · {t('{n} 筆', { n: m.entries.toLocaleString() })}</span> : null}
      </div>
      {m.status === 'error' ? (
        <Badge tone="warn">
          <span title={m.error ?? ''}>{t('最近一次失敗')}</span>
        </Badge>
      ) : stale ? (
        <Badge tone="warn">{t('過期')}</Badge>
      ) : null}
      <div className="mt-1">
        <FeedSyncButton only={[f.id]} compact />
      </div>
    </>
  );
}

function FeedTable({ t, feeds, stats, nc }: { t: TFn; feeds: FeedEntry[]; stats: Stats; nc: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-slate-500">
          <tr>
            <th className="py-1.5 pr-3">{t('來源')}</th>
            <th className="py-1.5 pr-3">{t('類型')}</th>
            <th className="py-1.5 pr-3">{t('信心')}</th>
            <th className="py-1.5 pr-3">{t('授權')}</th>
            <th className="py-1.5 pr-3">{t('更新間隔')}</th>
            <th className="py-1.5 pr-3">{t('Hub 最後同步')}</th>
            <th className="py-1.5 pr-3">{t('7 天命中')}</th>
          </tr>
        </thead>
        <tbody>
          {feeds.map((f) => {
            const s = stats.get(f.id);
            return (
              <tr key={f.id} className="border-t border-slate-100 align-top dark:border-slate-800">
                <td className="py-2 pr-3">
                  <a href={f.urls[0]} target="_blank" rel="noreferrer noopener" className="hover:underline">
                    <span className="font-medium">{f.vendor}</span> <span className="text-slate-500">{f.name}</span>
                  </a>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {f.enabled_default ? <Badge tone="ok">{t('預設啟用')}</Badge> : <Badge>{t('預設關閉')}</Badge>}
                    {f.tags.slice(0, 3).map((x) => (
                      <Badge key={x}>{x}</Badge>
                    ))}
                  </div>
                  {f.notes ? <div className="mt-1 text-xs text-slate-500">{f.notes}</div> : null}
                </td>
                <td className="py-2 pr-3 text-xs whitespace-nowrap">
                  {f.kind}
                  {f.direction !== 'both' ? <div className="text-slate-500">{directionLabel(t, f.direction === 'inbound' ? 'inbound' : 'outbound')}</div> : null}
                </td>
                <td className="py-2 pr-3 tabular-nums">{f.confidence}%</td>
                <td className="py-2 pr-3 text-xs">
                  <a href={f.license.url} target="_blank" rel="noreferrer noopener" className="hover:underline">
                    {f.license.name}
                  </a>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {f.license.commercial_ok ? <Badge tone="ok">{t('可商用')}</Badge> : <Badge tone="warn">{t('只限非商用')}</Badge>}
                    {f.license.attribution_required ? <Badge tone="info">{t('需標註來源')}</Badge> : null}
                  </div>
                </td>
                <td className="py-2 pr-3 text-xs whitespace-nowrap">{f.refresh_interval}</td>
                <td className="py-2 pr-3 text-xs whitespace-nowrap">
                  <MirrorCell t={t} f={f} m={readMeta(f.id)} nc={nc} />
                </td>
                <td className="py-2 pr-3 text-xs whitespace-nowrap">
                  {s ? (
                    <>
                      <div className="tabular-nums">{t('{n} 個指標、{h} 台主機', { n: s.indicators, h: s.hosts })}</div>
                      <div className="text-slate-500">{since(s.lastSeenAt, t)}</div>
                    </>
                  ) : (
                    <span className="text-slate-400">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default async function IntelPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireAdmin();
  const { t } = await getT();
  const sp = await searchParams;
  const q = strParam(sp, 'q', 100);
  const feeds = loadRegistry();
  const stats = await feedHitStats(7);
  syncInBackground();
  const hosts = await listAgents();
  const usage = await getIntelUsage(getDb());
  const nc = usage.usage === 'noncommercial';
  const mirrored = feeds.filter((f) => mirrorable(f, nc));
  const ncSources = feeds.filter((f) => !f.license.commercial_ok && f.enabled_default).map((f) => f.vendor + ' ' + f.name);
  const metas = mirrored.map((f) => readMeta(f.id));
  const okCount = metas.filter((m) => m?.sha256 && m.status === 'ok').length;
  const lastSync = metas.reduce<string | null>((a, m) => (m?.checked_at && (!a || m.checked_at > a) ? m.checked_at : a), null);
  const groups = (['threat', 'dns', 'geo', 'vuln', 'lookup'] as const)
    .map((g) => ({ g, feeds: feeds.filter((f) => feedGroup(f) === g) }))
    .filter((x) => x.feeds.length);
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('威脅情資')}</h1>
        <p className="text-sm text-slate-500">
          {t('agent 用來判定連線的公開情資來源。每筆命中都附廠商、授權與原始清單網址；只限非商業用途的來源只在選「個人／非商業用途」時使用。')}
        </p>
      </header>
      <Card title={t('情資來源授權')}>
        <IntelUsageSetting usage={usage.usage} locked={usage.source === 'env'} sources={ncSources} />
      </Card>
      <Card title={t('同步情資資料庫')}>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1 text-sm">
            <p>
              {t('Hub 鏡像：{ok}／{total} 個來源有最新資料，最後檢查 {at}。', { ok: okCount, total: mirrored.length, at: lastSync ? since(new Date(lastSync), t) : t('從未') })}
            </p>
            <p className="text-xs text-slate-500">
              {t('Hub 依每個來源的更新間隔自動向廠商抓清單；主機的 ai-security-monitor 會改從 Hub 下載（Hub 連不到時才直接找廠商），每 30 分鐘檢查一次。')}
            </p>
          </div>
          <FeedSyncButton />
        </div>
        {hosts.length ? (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-500">
                <tr>
                  <th className="py-1.5 pr-3">{t('主機')}</th>
                  <th className="py-1.5 pr-3">{t('情資最後更新')}</th>
                  <th className="py-1.5 pr-3">{t('來源')}</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => {
                  const old = !h.intelCheckedAt || Date.now() - h.intelCheckedAt.getTime() > 6 * 3_600_000;
                  return (
                    <tr key={h.id} className="border-t border-slate-100 dark:border-slate-800">
                      <td className="py-1.5 pr-3">
                        <Link href={`/agents/${encodeURIComponent(h.id)}`} className="hover:underline">
                          {h.hostname}
                        </Link>
                      </td>
                      <td className="py-1.5 pr-3 text-xs">
                        {h.intelCheckedAt ? since(h.intelCheckedAt, t) : <span className="text-slate-400">{t('尚未回報（需要新版 ai-security-monitor）')}</span>}{' '}
                        {h.intelCheckedAt && old ? <Badge tone="warn">{t('過期')}</Badge> : null}
                      </td>
                      <td className="py-1.5 pr-3 text-xs text-slate-500">
                        {h.intelFeeds ? t('{ok}／{total} 個清單', { ok: h.intelFeeds.ok, total: h.intelFeeds.total }) : '—'}
                        {h.intelFeeds?.source === 'hub' ? ` · ${t('從 Hub')}` : h.intelFeeds?.source === 'vendor' ? ` · ${t('直接找廠商')}` : ''}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
      <Card title={t('查 IP 或網域')}>
        <SearchBox t={t} action="/intel" q={q} keep={{}} placeholder={t('例：203.0.113.66')} />
      </Card>
      {q ? <IndicatorDetails t={t} q={q} /> : null}
      {groups.length ? (
        groups.map((x) => (
          <Card
            key={x.g}
            title={
              <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                {groupTitle(t, x.g)}
                {x.feeds.some((f) => mirrorable(f, nc)) ? <FeedSyncButton only={x.feeds.filter((f) => mirrorable(f, nc)).map((f) => f.id)} label={t('這一區全部更新')} compact /> : null}
              </span>
            }
          >
            <FeedTable t={t} feeds={x.feeds} stats={stats} nc={nc} />
          </Card>
        ))
      ) : (
        <EmptyState title={t('找不到情資登錄檔')}>{t('設定 ASA_HUB_FEEDS_DIR 指向 repo 的 feeds/ 目錄。')}</EmptyState>
      )}
    </div>
  );
}
