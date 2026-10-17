// IP 旁的外部風險圖示、排名表的「外部風險」欄、圖示說明。server／client 元件都能用（只吃 t）。
// 顏色之外每一級也用不同符號，色盲或黑白列印也分得出來；滑過看分數與查詢時間。
import { since } from '@/lib/format';
import type { TFn } from '@/lib/i18n/core';
import type { IpRisk, RiskLevel } from '@/lib/ipintel/types';

const ICON: Record<RiskLevel | 'unqueried', { glyph: string; cls: string }> = {
  low: { glyph: '✓', cls: 'bg-emerald-600 text-white' },
  medium: { glyph: '!', cls: 'bg-yellow-400 text-slate-900' },
  high: { glyph: '▲', cls: 'bg-orange-500 text-white' },
  critical: { glyph: '✕', cls: 'bg-red-600 text-white' },
  unqueried: { glyph: '?', cls: 'border border-slate-300 bg-slate-100 text-slate-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-400' },
};

const CHIP: Record<RiskLevel, string> = {
  low: 'bg-emerald-50 text-emerald-800 ring-emerald-600/30 dark:bg-emerald-950 dark:text-emerald-300',
  medium: 'bg-yellow-50 text-yellow-800 ring-yellow-500/40 dark:bg-yellow-950 dark:text-yellow-300',
  high: 'bg-orange-50 text-orange-800 ring-orange-500/40 dark:bg-orange-950 dark:text-orange-300',
  critical: 'bg-red-50 text-red-800 ring-red-600/40 dark:bg-red-950 dark:text-red-300',
};

/** 低／中／高／極高。 */
export function riskLevelShort(t: TFn, l: RiskLevel): string {
  return { low: t('低'), medium: t('中'), high: t('高'), critical: t('極高') }[l];
}

/** 滑過的說明：「外部風險：高（68 分，10 分鐘前查詢）」。 */
export function riskTitle(t: TFn, risk: IpRisk): string {
  if (risk.kind === 'private') return t('內網或保留位址：不會送給外部情資來源查詢');
  if (risk.kind === 'unqueried') return t('尚未查詢外部情資，點進去或在排名勾選後批次查詢');
  return t('外部風險：{level}（{score} 分，{at}查詢）', { level: riskLevelShort(t, risk.level), score: risk.score, at: since(risk.queriedAt, t) });
}

function Glyph({ k, label }: { k: RiskLevel | 'unqueried'; label: string }) {
  const s = ICON[k];
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={`inline-flex h-4 w-4 shrink-0 cursor-help select-none items-center justify-center rounded-full font-sans text-[10px] font-bold leading-none ${s.cls}`}
    >
      {s.glyph}
    </span>
  );
}

/** IP 旁的小圖示；內網位址不顯示（設計上就不查）。 */
export function IpRiskIcon({ t, risk }: { t: TFn; risk: IpRisk | null | undefined }) {
  if (!risk || risk.kind === 'private') return null;
  return <Glyph k={risk.kind === 'scored' ? risk.level : 'unqueried'} label={riskTitle(t, risk)} />;
}

/** 排名表「外部風險」欄：分數＋等級。 */
export function IpRiskBadge({ t, risk }: { t: TFn; risk: IpRisk }) {
  if (risk.kind === 'private') {
    return (
      <span className="cursor-help text-xs text-slate-400" title={riskTitle(t, risk)}>
        {t('內網')}
      </span>
    );
  }
  if (risk.kind === 'unqueried') {
    return (
      <span className="cursor-help text-slate-400" title={riskTitle(t, risk)}>
        —
      </span>
    );
  }
  return (
    <span
      className={`inline-flex cursor-help items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-semibold ring-1 ring-inset ${CHIP[risk.level]}`}
      title={riskTitle(t, risk)}
    >
      <span className="tabular-nums">{risk.score}</span>
      {riskLevelShort(t, risk.level)}
    </span>
  );
}

/** 圖示說明（排名表上方）。 */
export function IpRiskLegend({ t }: { t: TFn }) {
  const items: [RiskLevel | 'unqueried', string][] = [
    ['low', t('低（0–24 分）')],
    ['medium', t('中（25–49 分）')],
    ['high', t('高（50–74 分）')],
    ['critical', t('極高（75–100 分）')],
    ['unqueried', t('尚未查詢')],
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
      <span
        className="cursor-help underline decoration-dotted underline-offset-2"
        title={t('IP 旁的圖示是外部威脅情資（AbuseIPDB、GreyNoise 等第三方資料庫）算出的風險分數 0–100，越高越可能是惡意來源；內網位址不會查，所以不顯示。')}
      >
        {t('圖示說明')}
      </span>
      {items.map(([k, label]) => (
        <span key={k} className="inline-flex items-center gap-1">
          <Glyph k={k} label={label} />
          {label}
        </span>
      ))}
    </div>
  );
}
