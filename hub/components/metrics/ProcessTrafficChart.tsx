'use client';

// 各程式的網路流量圖：前幾名程式各一條線＋「其他」（虛線），可切換合計／下載／上傳。資料由 server 的 processSeries() 算好傳進來。
import { useState } from 'react';
import { TimeChart } from '@/components/charts/TimeChart';
import { useT } from '@/lib/i18n/client';
import type { ProcSeries } from '@/lib/queries/metrics';

const COLORS = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)', 'var(--chart-6)'];
type Metric = 'total' | 'rx' | 'tx';

const add = (a: (number | null)[], b: (number | null)[]) => a.map((v, i) => (v == null && b[i] == null ? null : (v ?? 0) + (b[i] ?? 0)));

export function ProcessTrafficChart({ times, series, timeMode, height = 220 }: { times: string[]; series: ProcSeries[]; timeMode: 'time' | 'date'; height?: number }) {
  const { t } = useT();
  const [metric, setMetric] = useState<Metric>('total');
  const label = { total: t('各程式的下載＋上傳速率'), rx: t('各程式的下載速率'), tx: t('各程式的上傳速率') }[metric];
  let color = 0;
  const lines = series.map((s) => ({
    label: s.name ?? t('其他程式'),
    color: s.name == null ? 'var(--chart-axis)' : COLORS[color++ % COLORS.length],
    dashed: s.name == null,
    values: metric === 'rx' ? s.rx : metric === 'tx' ? s.tx : add(s.rx, s.tx),
  }));
  return (
    <div className="space-y-2">
      <div role="group" aria-label={t('顯示')} className="inline-flex overflow-hidden rounded-md border border-slate-300 text-xs dark:border-slate-700">
        {(['total', 'rx', 'tx'] as const).map((m) => (
          <button
            key={m}
            type="button"
            aria-pressed={metric === m}
            onClick={() => setMetric(m)}
            className={`px-2.5 py-1 ${metric === m ? 'bg-teal-700 text-white' : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'}`}
          >
            {{ total: t('合計'), rx: t('下載'), tx: t('上傳') }[m]}
          </button>
        ))}
      </div>
      <TimeChart label={label} format="rate" height={height} timeMode={timeMode} times={times} series={lines} />
    </div>
  );
}
