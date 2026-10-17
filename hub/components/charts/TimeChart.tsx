'use client';
// 時間序列折線圖（純 SVG，不用圖表庫）：一條 y 軸、2px 線、滑過顯示十字線與各序列的值；有一份給螢幕閱讀器的表格。
import { useEffect, useMemo, useRef, useState } from 'react';
import { fmtBytes, fmtPct, fmtRate } from '@/lib/format';
import { useT } from '@/lib/i18n/client';

export interface ChartSeries {
  label: string;
  /** CSS 顏色（用 var(--chart-1) 這類 token，深淺色自動切換）。 */
  color: string;
  values: (number | null)[];
  /** 虛線（例如「最高」這種輔助線）。 */
  dashed?: boolean;
}

export type ChartFormat = 'rate' | 'pct' | 'bytes' | 'number';

function fmt(v: number | null | undefined, f: ChartFormat): string {
  if (v == null) return '—';
  if (f === 'rate') return fmtRate(v);
  if (f === 'pct') return fmtPct(v);
  if (f === 'bytes') return fmtBytes(v);
  return v.toFixed(v >= 10 ? 0 : 1);
}

/** 把最大值往上取到好讀的刻度（1、2、5 × 10^k；位元組用 1024 的倍數）。 */
export function niceMax(v: number, f: ChartFormat): number {
  if (f === 'pct') return 100;
  if (!(v > 0)) return 1;
  if (f === 'rate' || f === 'bytes') {
    let unit = 1;
    while (v / unit >= 1024) unit *= 1024;
    const x = v / unit;
    const step = [1, 2, 4, 5, 8, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 1024].find((s) => s >= x) ?? 1024;
    return step * unit;
  }
  const p = 10 ** Math.floor(Math.log10(v));
  const step = [1, 2, 5, 10].find((s) => s * p >= v) ?? 10;
  return step * p;
}

function timeLabel(iso: string, mode: 'time' | 'date'): string {
  // 一律 UTC（頁面上其他時間也是 UTC）
  return mode === 'time' ? iso.slice(11, 16) : iso.slice(5, 10);
}

export function TimeChart({
  times,
  series,
  format,
  height = 160,
  label,
  timeMode = 'time',
  emptyText,
}: {
  times: string[];
  series: ChartSeries[];
  format: ChartFormat;
  height?: number;
  /** 圖的名稱（螢幕閱讀器與表格標題）。 */
  label: string;
  timeMode?: 'time' | 'date';
  emptyText?: string;
}) {
  const { t } = useT();
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    const el = box.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(240, Math.round(e[0].contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const pad = { l: 64, r: 12, t: 8, b: 22 };
  const w = Math.max(1, width - pad.l - pad.r);
  const h = Math.max(1, height - pad.t - pad.b);
  const n = times.length;
  const all = series.flatMap((s) => s.values).filter((v): v is number => v != null);
  const max = useMemo(() => niceMax(all.length ? Math.max(...all) : 0, format), [all, format]);
  const x = (i: number) => pad.l + (n <= 1 ? w / 2 : (i / (n - 1)) * w);
  const y = (v: number) => pad.t + h - (Math.min(v, max) / max) * h;
  const paths = series.map((s) => {
    let d = '';
    let pen = false;
    s.values.forEach((v, i) => {
      if (v == null) {
        pen = false;
        return;
      }
      d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
      pen = true;
    });
    return d;
  });
  // 只有單獨一點（前後都沒資料）時畫成點，不然看不到
  const lonely = series.map((s) => s.values.map((v, i) => (v != null && s.values[i - 1] == null && s.values[i + 1] == null ? i : -1)).filter((i) => i >= 0));
  const ticks = n > 1 ? [0, Math.round((n - 1) / 3), Math.round(((n - 1) * 2) / 3), n - 1] : [0];
  const onMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * width;
    if (n < 1) return;
    const i = Math.round(((px - pad.l) / w) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  };
  const empty = all.length === 0;
  const latest = (s: ChartSeries) => [...s.values].reverse().find((v) => v != null);
  const step = Math.max(1, Math.ceil(n / 48));
  return (
    <figure className="space-y-2">
      {series.length > 1 ? (
        <figcaption className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600 dark:text-slate-300">
          {series.map((s) => (
            <span key={s.label} className="inline-flex items-center gap-1.5">
              <svg width="16" height="8" aria-hidden>
                <line x1="0" x2="16" y1="4" y2="4" stroke={s.color} strokeWidth="2" strokeDasharray={s.dashed ? '4 3' : undefined} />
              </svg>
              {s.label}
              <span className="tabular-nums text-slate-500">{fmt(latest(s), format)}</span>
            </span>
          ))}
        </figcaption>
      ) : null}
      <div ref={box} className="relative w-full" style={{ height }}>
        <svg
          width={width}
          height={height}
          role="img"
          aria-label={label}
          className="block touch-none select-none"
          onPointerMove={onMove}
          onPointerLeave={() => setHover(null)}
        >
          {[0, 0.5, 1].map((f) => (
            <g key={f}>
              <line x1={pad.l} x2={pad.l + w} y1={pad.t + h - f * h} y2={pad.t + h - f * h} stroke="var(--chart-grid)" strokeWidth="1" />
              <text x={pad.l - 6} y={pad.t + h - f * h + 4} textAnchor="end" fontSize="11" fill="var(--chart-axis)" className="tabular-nums">
                {fmt(max * f, format)}
              </text>
            </g>
          ))}
          {ticks.map((i) => (
            <text key={i} x={x(i)} y={height - 6} textAnchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'} fontSize="11" fill="var(--chart-axis)">
              {times[i] ? timeLabel(times[i], timeMode) : ''}
            </text>
          ))}
          {paths.map((d, k) =>
            d ? (
              <path
                key={k}
                d={d}
                fill="none"
                stroke={series[k].color}
                strokeWidth="2"
                strokeLinejoin="round"
                strokeLinecap="round"
                strokeDasharray={series[k].dashed ? '4 3' : undefined}
              />
            ) : null,
          )}
          {lonely.map((idx, k) => idx.map((i) => <circle key={`${k}-${i}`} cx={x(i)} cy={y(series[k].values[i] as number)} r="2.5" fill={series[k].color} />))}
          {hover != null ? (
            <g pointerEvents="none">
              <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={pad.t + h} stroke="var(--chart-axis)" strokeWidth="1" strokeDasharray="2 2" />
              {series.map((s, k) =>
                s.values[hover] != null ? (
                  <circle key={k} cx={x(hover)} cy={y(s.values[hover] as number)} r="4" fill={s.color} stroke="var(--chart-surface)" strokeWidth="2" />
                ) : null,
              )}
            </g>
          ) : null}
          {empty ? (
            <text x={pad.l + w / 2} y={pad.t + h / 2} textAnchor="middle" fontSize="12" fill="var(--chart-axis)">
              {emptyText ?? t('這段期間沒有資料')}
            </text>
          ) : null}
        </svg>
        {hover != null && !empty ? (
          <div
            className="pointer-events-none absolute top-1 z-10 min-w-36 rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs shadow-md dark:border-slate-700 dark:bg-slate-800"
            style={x(hover) > width / 2 ? { right: width - x(hover) + 10 } : { left: x(hover) + 10 }}
          >
            <div className="mb-1 font-medium text-slate-700 dark:text-slate-200">{times[hover]?.slice(0, 16).replace('T', ' ')} UTC</div>
            {series.map((s) => (
              <div key={s.label} className="flex items-center justify-between gap-3">
                <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
                  <span className="inline-block h-0.5 w-3" style={{ background: s.color }} aria-hidden />
                  {s.label}
                </span>
                <span className="tabular-nums text-slate-900 dark:text-slate-100">{fmt(s.values[hover], format)}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
      <table className="sr-only">
        <caption>{label}</caption>
        <thead>
          <tr>
            <th>{t('時間（UTC）')}</th>
            {series.map((s) => (
              <th key={s.label}>{s.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {times
            .map((tm, i) => ({ tm, i }))
            .filter(({ i }) => i % step === 0)
            .map(({ tm, i }) => (
              <tr key={tm}>
                <td>{tm.slice(0, 16).replace('T', ' ')}</td>
                {series.map((s) => (
                  <td key={s.label}>{fmt(s.values[i], format)}</td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </figure>
  );
}
