import Link from 'next/link';
import { IndicatorDetails } from '@/components/security/IndicatorDetails';
import { DirectionBadge, VerdictChip, directionLabel } from '@/components/security/Verdict';
import { Badge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { SearchBox } from '@/components/ui/Filters';
import { requireAdmin } from '@/lib/auth/require';
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import { getT } from '@/lib/i18n/server';
import { feedGroup, loadRegistry, type FeedEntry } from '@/lib/intel/registry';
import { strParam } from '@/lib/queries/params';
import { feedHitStats } from '@/lib/queries/intel';

export const dynamic = 'force-dynamic';

type Stats = Awaited<ReturnType<typeof feedHitStats>>;

function groupTitle(t: TFn, g: ReturnType<typeof feedGroup>): string {
  return {
    threat: t('威脅指標（IP／網段／網域）'),
    geo: t('地理位置與 ASN'),
    vuln: t('漏洞資料'),
    lookup: t('線上名譽查詢（需自備 API key，預設關閉）'),
  }[g];
}

function FeedTable({ t, feeds, stats }: { t: TFn; feeds: FeedEntry[]; stats: Stats }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-slate-500">
          <tr>
            <th className="py-1.5 pr-3">{t('來源')}</th>
            <th className="py-1.5 pr-3">{t('類型')}</th>
            <th className="py-1.5 pr-3">{t('信心')}</th>
            <th className="py-1.5 pr-3">{t('授權')}</th>
            <th className="py-1.5 pr-3">{t('更新')}</th>
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
                    {f.license.commercial_ok ? <Badge tone="ok">{t('可商用')}</Badge> : <Badge tone="warn">{t('非商用：只告警不封鎖')}</Badge>}
                    {f.license.attribution_required ? <Badge tone="info">{t('需標註來源')}</Badge> : null}
                  </div>
                </td>
                <td className="py-2 pr-3 text-xs whitespace-nowrap">{f.refresh_interval}</td>
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
  const groups = (['threat', 'geo', 'vuln', 'lookup'] as const)
    .map((g) => ({ g, feeds: feeds.filter((f) => feedGroup(f) === g) }))
    .filter((x) => x.feeds.length);
  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">{t('威脅情資')}</h1>
        <p className="text-sm text-slate-500">
          {t('agent 用來判定連線的公開情資來源。每筆命中都附廠商、授權與原始清單網址；非商用授權的來源只告警，不會自動封鎖。')}
        </p>
      </header>
      <Card title={t('查 IP 或網域')}>
        <SearchBox t={t} action="/intel" q={q} keep={{}} placeholder={t('例：203.0.113.66')} />
      </Card>
      {q ? <IndicatorDetails t={t} q={q} /> : null}
      {groups.length ? (
        groups.map((x) => (
          <Card key={x.g} title={groupTitle(t, x.g)}>
            <FeedTable t={t} feeds={x.feeds} stats={stats} />
          </Card>
        ))
      ) : (
        <EmptyState title={t('找不到情資登錄檔')}>{t('設定 ASA_HUB_FEEDS_DIR 指向 repo 的 feeds/ 目錄。')}</EmptyState>
      )}
    </div>
  );
}
