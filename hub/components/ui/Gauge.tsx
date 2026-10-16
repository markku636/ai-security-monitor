// 分數圓環（純 SVG，不用圖表庫）。

function tone(score: number): string {
  if (score >= 90) return '#15803d';
  if (score >= 70) return '#65a30d';
  if (score >= 50) return '#d97706';
  return '#b91c1c';
}

export function Gauge({ score, label, size = 96 }: { score: number | null | undefined; label: string; size?: number }) {
  const r = 40;
  const c = 2 * Math.PI * r;
  const v = score == null ? 0 : Math.max(0, Math.min(100, score));
  return (
    <figure className="flex flex-col items-center gap-1">
      <svg width={size} height={size} viewBox="0 0 100 100" role="img" aria-label={`${label}: ${score ?? '—'}`}>
        <circle cx="50" cy="50" r={r} fill="none" strokeWidth="10" className="stroke-slate-200 dark:stroke-slate-800" />
        {score != null ? (
          <circle
            cx="50"
            cy="50"
            r={r}
            fill="none"
            strokeWidth="10"
            stroke={tone(v)}
            strokeLinecap="round"
            strokeDasharray={`${(v / 100) * c} ${c}`}
            transform="rotate(-90 50 50)"
          />
        ) : null}
        <text x="50" y="56" textAnchor="middle" className="fill-current text-[22px] font-semibold tabular-nums">
          {score ?? '—'}
        </text>
      </svg>
      <figcaption className="text-xs text-slate-500">{label}</figcaption>
    </figure>
  );
}
