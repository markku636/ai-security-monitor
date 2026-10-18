// 可疑 IP 完整清單：整份排名可翻頁、排序、時間範圍、主機與「只看未分析」篩選；勾選跨頁保留，可一鍵查全部未分析的外部情資。
import { BackButton } from '@/components/ui/BackButton';
import { RiskyIpRanking } from '@/components/security/RiskyIpRanking';
import { FilterChip, FilterRow, Pager } from '@/components/ui/Filters';
import { HostFilter } from '@/components/ui/HostFilter';
import { requireAdmin } from '@/lib/auth/require';
import { getT } from '@/lib/i18n/server';
import {
  parseRankSort,
  parseRankWindow,
  RANK_SORT_DEFAULT_DIR,
  riskyIpRanking,
  unanalyzedRiskyIps,
  type RankSortKey,
  type RankWindow,
} from '@/lib/queries/connections';
import { clampInt, strParam } from '@/lib/queries/params';

export const dynamic = 'force-dynamic';

const PAGE = 50;
const BASE = '/connections/ips';

type Params = Record<string, string | string[] | undefined>;

/** 保留目前的篩選條件，只改指定參數（值為 undefined 就拿掉）。 */
function withParams(params: Params, patch: Record<string, string | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (k in patch || v == null) continue;
    for (const one of Array.isArray(v) ? v : [v]) q.append(k, one);
  }
  for (const [k, v] of Object.entries(patch)) if (v !== undefined) q.set(k, v);
  const s = q.toString();
  return `${BASE}${s ? `?${s}` : ''}`;
}

export default async function RiskyIpListPage({ searchParams }: { searchParams: Promise<Params> }) {
  await requireAdmin();
  const { t } = await getT();
  const params = await searchParams;
  const agentId = strParam(params, 'agent_id', 64);
  const sort = parseRankSort(params);
  const rankWindow = parseRankWindow(params);
  const onlyUnanalyzed = strParam(params, 'unan', 4) === '1';
  const offset = clampInt(params, 'offset', 0, 0, 1_000_000);
  const [ranking, unanalyzed] = await Promise.all([
    riskyIpRanking(PAGE, agentId, sort, rankWindow, { offset, unanalyzed: onlyUnanalyzed }),
    unanalyzedRiskyIps(agentId, rankWindow),
  ]);
  // 換排序／範圍／篩選都回第一頁
  const windowHref = (w: RankWindow) => withParams(params, { rwin: w === '30' ? undefined : w, offset: undefined });
  const sortHref = (k: RankSortKey) =>
    withParams(params, {
      rsort: k,
      rdir: sort.key === k ? (sort.dir === 'asc' ? 'desc' : 'asc') : RANK_SORT_DEFAULT_DIR[k],
      offset: undefined,
    });
  const keep: Record<string, string | undefined> = {};
  for (const k of ['rsort', 'rdir', 'rwin', 'unan']) {
    const v = strParam(params, k, 16);
    if (v) keep[k] = v;
  }
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <BackButton fallback="/connections" />
          <h1 className="text-xl font-semibold">{t('可疑 IP 清單')}</h1>
          <p className="text-sm text-slate-500">
            {t('所有曾被判定可疑或危險的遠端 IP。可以翻頁勾選（換頁不會清掉），再一次查詢外部情資；或直接「查詢全部未分析」。')}
          </p>
        </div>
      </header>
      <RiskyIpRanking
        t={t}
        ranking={ranking}
        sort={sort}
        sortHref={sortHref}
        rankWindow={rankWindow}
        windowHref={windowHref}
        unanalyzed={unanalyzed}
        persistKey="asm.ip-list.selected"
        emptyText={onlyUnanalyzed ? t('這個範圍裡的公網 IP 都查過外部情資了。') : undefined}
        toolbar={
          <div className="space-y-2">
            <HostFilter t={t} action={BASE} current={agentId} keep={keep} />
            <FilterRow label={t('情資')}>
              <FilterChip href={withParams(params, { unan: undefined, offset: undefined })} active={!onlyUnanalyzed}>
                {t('全部')}
              </FilterChip>
              <FilterChip href={withParams(params, { unan: '1', offset: undefined })} active={onlyUnanalyzed}>
                {t('只看未分析')} <span className="opacity-70">{unanalyzed.total}</span>
              </FilterChip>
            </FilterRow>
          </div>
        }
        footer={
          <Pager
            t={t}
            total={ranking.total}
            limit={PAGE}
            offset={offset}
            hrefFor={(o) => withParams(params, { offset: o ? String(o) : undefined })}
          />
        }
      />
    </div>
  );
}
