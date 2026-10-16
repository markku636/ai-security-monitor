import type { SevCounts } from '@/drizzle/schema';
import type { TFn } from '@/lib/i18n/core';

const ORDER: (keyof SevCounts)[] = ['critical', 'high', 'medium', 'low', 'info'];

const DOT: Record<keyof SevCounts, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};

export function sevLabel(t: TFn, s: keyof SevCounts): string {
  return { critical: t('嚴重'), high: t('高'), medium: t('中'), low: t('低'), info: t('資訊') }[s];
}

/** 一列嚴重度計數（0 的淡化）。 */
export function SevCountsRow({ counts, t }: { counts: SevCounts; t: TFn }) {
  return (
    <div className="flex flex-wrap gap-3 text-sm">
      {ORDER.map((k) => (
        <span key={k} className={`inline-flex items-center gap-1.5 ${counts[k] ? '' : 'opacity-40'}`}>
          <span className={`h-2.5 w-2.5 rounded-full ${DOT[k]}`} aria-hidden />
          <span className="tabular-nums font-medium">{counts[k]}</span>
          <span className="text-slate-500">{sevLabel(t, k)}</span>
        </span>
      ))}
    </div>
  );
}

export function ScorePill({ score }: { score: number | null | undefined }) {
  if (score == null) return <span className="text-slate-400">—</span>;
  const tone =
    score >= 90 ? 'text-green-700 dark:text-green-400' : score >= 70 ? 'text-lime-700 dark:text-lime-400' : score >= 50 ? 'text-amber-700 dark:text-amber-400' : 'text-red-700 dark:text-red-400';
  return <span className={`font-semibold tabular-nums ${tone}`}>{score}</span>;
}
